#include <assert.h>
#include <libssh2.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Способ аутентификации
enum AUTH_PW {
	AUTH_PW_PASSWORD = 0b001,
	AUTH_PW_KEYBOARD_INTERACTIVE = 0b010,
	AUTH_PW_PUBLICKEY = 0b100
};

static in_port_t const DEFAULT_PORT = 22;

static char const * const AUTH_PASSWORD_KEY = "-p";
static char const * const AUTH_PUBLICKEY_KEY = "-k";
static char const * const AUTH_INTERACTIVE_KEY = "-i";

static char const * const pubkey = ".ssh/id_rsa.pub";
static char const * const privkey = ".ssh/id_rsa";

char const * username = "username";
char const * password = "password";

void usage(char const * prog_path);
void print_fingerprint(FILE *, char const * fingerprint);

int communication_cycle(LIBSSH2_CHANNEL *);

int set_destination(struct sockaddr_in * addr_to_set,
		    int prog_argc,
		    char const ** prog_argv);

int authentication(LIBSSH2_SESSION * session,
		   char const * username,
		   char const * passwd,
		   int prog_argc,
		   char const ** prog_argv);

static void
kbd_callback([[maybe_unused]] char const * name,
	     [[maybe_unused]] int name_len,
	     [[maybe_unused]] char const * instruction,
	     [[maybe_unused]] int instruction_len,
	     int num_prompts,
	     [[maybe_unused]] const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts,
	     LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
	     [[maybe_unused]] void ** abstract)
{
	if (num_prompts != 1)
		return;

	responses[0].text = strdup(password);
	responses[0].length = (unsigned int)strlen(password);
}

int main(int argc, char const * argv[])
{
	libssh2_socket_t sock = LIBSSH2_INVALID_SOCKET;
	int rc;
	LIBSSH2_SESSION * session = NULL;

	if (argc < 2) {
		usage(*argv);
		return 0;
	}

#ifdef _WIN32
	WSADATA wsadata;

	rc = WSAStartup(MAKEWORD(2, 0), &wsadata);
	if (rc) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
		return 1;
	}
#endif

	struct sockaddr_in sin;
	rc = set_destination(&sin, argc, argv);
	if (rc) {
		fprintf(stderr, "Invalid IP address!\n");
		goto shutdown;
	}

	if (argc > 2) {
		username = argv[2];
	}
	if (argc > 3) {
		password = argv[3];
	}

	rc = libssh2_init(0);

	if (rc) {
		fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
		goto shutdown;
	}

	/* Ultra basic "connect to port 22 on localhost".  Your code is
	 * responsible for creating the socket establishing the connection
	 */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == LIBSSH2_INVALID_SOCKET) {
		fprintf(stderr, "failed to create socket.\n");
		rc = 1;
		goto shutdown;
	}

	fprintf(stderr, "Connecting to %s:%d as user %s\n",
		inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), username);

	if (connect(sock, (struct sockaddr *)(&sin),
		    sizeof(struct sockaddr_in))) {
		fprintf(stderr, "failed to connect.\n");
		goto shutdown;
	}

	/* Create a session instance and start it up. This will trade welcome
	 * banners, exchange keys, and setup crypto, compression, and MAC layers
	 */
	session = libssh2_session_init();
	if (!session) {
		fprintf(stderr, "Could not initialize SSH session.\n");
		goto shutdown;
	}

	/* Enable all debugging when libssh2 was built with debugging enabled */
	libssh2_trace(session, ~0);

	rc = libssh2_session_handshake(session, sock);
	if (rc) {
		fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
		goto shutdown;
	}

	/* At this point we have not yet authenticated.  The first thing to do
	 * is check the hostkey's fingerprint against our known hosts Your app
	 * may have it hard coded, may go to a file, may present it to the
	 * user, that's your call
	 */
	char const * fingerprint;
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	print_fingerprint(stderr, fingerprint);

	rc = authentication(session, username, password, argc, argv);
	if (rc)
		goto shutdown;

	/* Request a session channel on which to run a shell */
	LIBSSH2_CHANNEL * channel;
	channel = libssh2_channel_open_session(session);
	if (!channel) {
		fprintf(stderr, "Unable to open a session\n");
		goto shutdown;
	}

	/* Some environment variables may be set,
	 * It's up to the server which ones it'll allow though
	 */
	// libssh2_channel_setenv(channel, "FOO", "bar");

	/* Request a terminal with 'vanilla' terminal emulation
	 * See /etc/termcap for more options. This is useful when opening
	 * an interactive shell.
	 */
	if (libssh2_channel_request_pty(channel, "vanilla")) {
		fprintf(stderr, "Failed requesting pty\n");
	}

	if (argc > 5) {
		rc = communication_cycle(channel);
		if (rc)
			goto shutdown;
	}

	rc = libssh2_channel_get_exit_status(channel);

	if (libssh2_channel_close(channel))
		fprintf(stderr, "Unable to close channel\n");

	if (channel) {
		libssh2_channel_free(channel);
		channel = NULL;
	}

	/* Other channel types are supported via:
	 * libssh2_scp_send()
	 * libssh2_scp_recv2()
	 * libssh2_channel_direct_tcpip()
	 */

shutdown:
	if (session) {
		libssh2_session_disconnect(session, "Normal Shutdown");
		libssh2_session_free(session);
	}

	if (sock != LIBSSH2_INVALID_SOCKET) {
		shutdown(sock, 2);
		LIBSSH2_SOCKET_CLOSE(sock);
	}

	fprintf(stderr, "all done\n");
	libssh2_exit();

#ifdef _WIN32 // in shutdown
	WSACleanup();
#endif
	return rc;
}

void print_fingerprint(FILE * stream, char const * fingerprint)
{
	fprintf(stream, "Fingerprint: ");
	for (int i = 0; i < 20; i++) {
		fprintf(stream, "%02X ", (unsigned char)fingerprint[i]);
	}
	fprintf(stream, "\n");
}

void usage(char const * prog_path)
{
	fprintf(stderr,
		"Использование программы:\n"
		"%s ip логин пароль способ_аутентификации команда\n"
		"Возможные ключи:\n"
		"\t%s -- по паролю\n"
		"\t%s -- по публичному ключу\n"
		"\t%s -- интерактивный ввод\n", //
		prog_path, AUTH_PASSWORD_KEY, AUTH_PUBLICKEY_KEY,
		AUTH_INTERACTIVE_KEY);
}

int communication_cycle(LIBSSH2_CHANNEL * channel)
{
	// if (libssh2_channel_exec(channel, argv[5])) {
	//
	// 	fprintf(stderr,
	// 		"Unable to request command on channel\n");
	// 	goto shutdown;
	// }

	/* Instead of just running a single command with
	 * libssh2_channel_exec, a shell can be opened on the channel
	 * instead, for interactive use. You usually want a pty
	 * allocated first in that case (see above). */
	if (libssh2_channel_shell(channel)) {

		fprintf(stderr, "Unable to request shell on allocated pty\n");
		return -1;
	}

	/* At this point the shell can be interacted with using
	 * libssh2_channel_read()
	 * libssh2_channel_read_stderr()
	 * libssh2_channel_write()
	 * libssh2_channel_write_stderr()
	 *
	 * Blocking mode may be (en|dis)abled with:
	 *    libssh2_channel_set_blocking()
	 * If the server send EOF, libssh2_channel_eof() will return
	 * non-0 To send EOF to the server use:
	 * libssh2_channel_send_eof() A channel can be closed with:
	 * libssh2_channel_close() A channel can be freed with:
	 * libssh2_channel_free()
	 */

	/* Read and display all the data received on stdout (ignoring
	 * stderr) until the channel closes. This will eventually block
	 * if the command produces too much data on stderr; the loop
	 * must be rewritten to use non-blocking mode and include
	 * interspersed calls to libssh2_channel_read_stderr() to avoid
	 * this. See ssh2_echo.c for an idea of how such a loop might
	 * look.
	 */
	while (!libssh2_channel_eof(channel)) {

		char buf[1024];
		ssize_t err = libssh2_channel_read(channel, buf, sizeof(buf));

		if (err < 0)
			fprintf(stderr, "Unable to read response: %ld\n", err);
		else {
			fwrite(buf, 1, (size_t)err, stdout);
		}

		char const * response = "\x04";
		err = libssh2_channel_write(channel, response,
					    strlen(response));

		if (err < 0)
			fprintf(stderr, "Unable to write response: %ld\n", err);
		// sleep(4);
	}
	return 0;
}

int set_auth_ways(char const * userauthlist)
{
	int auth_pw = 0;
	if (strstr(userauthlist, "password")) {
		auth_pw |= AUTH_PW_PASSWORD;
	}
	if (strstr(userauthlist, "keyboard-interactive")) {
		auth_pw |= AUTH_PW_KEYBOARD_INTERACTIVE;
	}
	if (strstr(userauthlist, "publickey")) {
		auth_pw |= AUTH_PW_PUBLICKEY;
	}
	return auth_pw;
}

int set_auth_way(int prog_argc,
		 char const ** prog_argv,
		 char const * userauthlist)
{
	int auth_pw = set_auth_ways(userauthlist);
	for (int i = 0; i < prog_argc; ++i) {
		char const * key = prog_argv[i];
		assert(key != nullptr);
		if (key[0] != '-')
			continue;

		if ((auth_pw & AUTH_PW_PASSWORD) &&
		    !strcmp(key, AUTH_PASSWORD_KEY)) {
			return AUTH_PW_PASSWORD;
		}
		if ((auth_pw & AUTH_PW_KEYBOARD_INTERACTIVE) &&
		    !strcmp(key, AUTH_INTERACTIVE_KEY)) {
			return AUTH_PW_KEYBOARD_INTERACTIVE;
		}
		if ((auth_pw & AUTH_PW_PUBLICKEY) &&
		    !strcmp(key, AUTH_PUBLICKEY_KEY)) {
			return AUTH_PW_PUBLICKEY;
		}
	}
	// Если ключа не было, оставить как есть, несколько способов
	return auth_pw;
}

int authentication(LIBSSH2_SESSION * session,
		   char const * username,
		   char const * passwd,
		   int prog_argc,
		   char const ** prog_argv)
{
	/* check what authentication methods are available */
	char * userauthlist = libssh2_userauth_list(session, username,
						    (uint32_t)strlen(username));
	if (!userauthlist)
		return 0;

	// if userauthlist
	fprintf(stderr, "Authentication methods: %s\n", userauthlist);

	/* check for options */
	int auth_pw = set_auth_way(prog_argc, prog_argv, userauthlist);

	if (auth_pw & AUTH_PW_KEYBOARD_INTERACTIVE) {
		/* Or via keyboard-interactive */
		if (libssh2_userauth_keyboard_interactive(session, username,
							  &kbd_callback)) {
			fprintf(stderr, "Authentication by "
					"keyboard-interactive failed.\n");
			return -1;
		} else {
			fprintf(stderr, "Authentication by "
					"keyboard-interactive succeeded.\n");
		}
	} else if (auth_pw & AUTH_PW_PASSWORD) {
		/* We could authenticate via password */
		if (libssh2_userauth_password(session, username, passwd)) {

			fprintf(stderr, "Authentication by password failed.\n");
			return -1;
		} else {
			fprintf(stderr, "Authentication by password "
					"succeeded.\n");
		}
	} else if (auth_pw & AUTH_PW_PUBLICKEY) {
		/* Or by public key */
		size_t fn1sz, fn2sz;
		char *fn1, *fn2;

		char const * h = getenv("HOME");
		if (!h || !*h)
			h = ".";

		fn1sz = strlen(h) + strlen(pubkey) + 2;
		fn2sz = strlen(h) + strlen(privkey) + 2;
		fn1 = malloc(fn1sz + fn2sz);
		if (!fn1) {
			free(fn1);
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		fn2 = fn1 + fn1sz;

		snprintf(fn1, fn1sz, "%s/%s", h, pubkey);
		snprintf(fn2, fn2sz, "%s/%s", h, privkey);

		if (libssh2_userauth_publickey_fromfile(session, username, fn1,
							fn2, passwd)) {
			fprintf(stderr, "Authentication by public key "
					"failed.\n");
			free(fn1);
			return -1;
		} else {
			fprintf(stderr, "Authentication by public key "
					"succeeded.\n");
		}
		free(fn1);
	} else {
		fprintf(stderr, "No supported authentication methods found.\n");
		return -1;
	}
	return 0;
}

int set_destination(struct sockaddr_in * addr_to_set,
		    int prog_argc,
		    char const ** prog_argv)
{
	char ip_str_buf[16] = {};

	char const * non_key_param = nullptr;
	for (int i = 1; i < prog_argc; ++i) {
		char const * cur_param = prog_argv[i];
		if (cur_param[0] == '-')
			continue;

		non_key_param = cur_param;
		break;
	}
	if (!non_key_param)
		return -1;

	memset(addr_to_set, 0, sizeof(*addr_to_set));
	addr_to_set->sin_family = AF_INET;

	char const * ip_str;
	char const * port_str = strchr(non_key_param, ':');
	if (!port_str) {
		//Установка стандартного порта
		addr_to_set->sin_port = htons(DEFAULT_PORT);
		ip_str = non_key_param;
	} else {
		// Копирование IP-адреса в отдельный буфер без :порта
		ssize_t len = port_str - non_key_param;
		assert(len >= 0);
		if (len > 15)
			return -1;

		ip_str = strncpy(ip_str_buf, non_key_param, (size_t)len);

		// Непосредственно установка порта
		int new_port = atoi(++port_str);
		addr_to_set->sin_port = (new_port < 1 || new_port > UINT16_MAX)
						? htons(DEFAULT_PORT)
						: htons((in_port_t)new_port);
	}

	// Установка IP адреса
	addr_to_set->sin_addr.s_addr = inet_addr(ip_str);
	if (addr_to_set->sin_addr.s_addr == (in_addr_t)-1)
		return -1;

	return 0;
}
