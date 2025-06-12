#include "main.h"

int main(int argc, char const * argv[])
{
	libssh2_socket_t sock = LIBSSH2_INVALID_SOCKET;
	int rc;
	LIBSSH2_SESSION * session = NULL;

	if (argc < 2) {
		usage(*argv);
		return 0;
	}

	struct sockaddr_in sin;
	rc = set_destination(&sin, argc, argv);
	if (rc) {
		fprintf(stderr, "Invalid IP address!\n");
		return -1;
	}

	char const * username = get_username(argc, argv);

#ifdef _WIN32
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 0), &wsadata)) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", rc);
		return -1;
	}
#endif

	rc = libssh2_init(0);
	if (rc) {
		fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
		goto shutdown;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == LIBSSH2_INVALID_SOCKET) {
		fprintf(stderr, "failed to create socket.\n");
		rc = 1;
		goto shutdown;
	}

	fprintf(stderr, "Подключение к %s@%s:%d\n", username,
		inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	if (connect(sock, (struct sockaddr *)(&sin),
		    sizeof(struct sockaddr_in))) {
		fprintf(stderr, "Не удалось подключиться!\n");
		goto shutdown;
	}

	session = libssh2_session_init();
	if (!session) {
		fprintf(stderr, "Не удалось инициировать SSH сессию\n");
		goto shutdown;
	}

	rc = libssh2_session_handshake(session, sock);
	if (rc) {
		fprintf(stderr, "Не удалось установить SSH сессию: %d\n", rc);
		goto shutdown;
	}

	rc = authentication(session, username, argc, argv);
	if (rc)
		goto shutdown;

	LIBSSH2_CHANNEL * channel;
	channel = libssh2_channel_open_session(session);
	if (!channel) {
		fprintf(stderr, "Не удалось открыть канал\n");
		goto shutdown;
	}

	/* Request a terminal with 'vanilla' terminal emulation
	 * See /etc/termcap for more options. This is useful when opening
	 * an interactive shell.
	 */
	if (libssh2_channel_request_pty(channel, "vanilla")) {
		fprintf(stderr, "Failed requesting pty\n");
	}

	// Непосредственно взаимодействие с сервером
	int cmds_start = get_communication_type(argc, argv);
	if (cmds_start == -1) {
		rc = communication_cycle(channel);
	} else {
		cmds_start++;
		rc = communication_single_command(channel, argc - cmds_start,
						  argv + cmds_start);
	}
	if (rc)
		goto shutdown;

	rc = libssh2_channel_get_exit_status(channel);

	if (libssh2_channel_close(channel))
		fprintf(stderr, "Ошибка при закрытии канала\n");

	if (channel) {
		libssh2_channel_free(channel);
		channel = NULL;
	}

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

// Глобальный указатель для колбека ниже
char const * g_password = nullptr;

static void kbd_callback(char const *,
			 int,
			 char const *,
			 int,
			 int num_prompts,
			 const LIBSSH2_USERAUTH_KBDINT_PROMPT *,
			 LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
			 void **)
{
	if (num_prompts != 1)
		return;

	responses[0].text = strdup(g_password);
	responses[0].length = (unsigned int)strlen(g_password);
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
		"%s ip[:порт] [-u=логин] способ_аутентификации [-c команды]\n"
		"Если не указывать порт, используется 22\n"
		"Если не указывать пользователя, будет использоваться текущий\n"
		"Способы аутентификации:\n"
		"\t%s[=пароль] -- по паролю в параметре или ручным вводом\n"
		"\t%s -- по публичному ключу\n"
		"\t%s -- интерактивный ввод\n", //
		prog_path, AUTH_PASSWORD_INTERACTIVE_KEY, AUTH_PUBLICKEY_KEY,
		AUTH_INTERACTIVE_KEY);
}

int communication_cycle(LIBSSH2_CHANNEL * channel)
{
	if (libssh2_channel_shell(channel)) {
		fprintf(stderr, "Unable to request shell on allocated pty\n");
		return -1;
	}

	constexpr ssize_t r_buf_size = 1024;
	constexpr ssize_t w_buf_size = 128;
	char r_buf[r_buf_size + 1];
	char w_buf[w_buf_size + 1];

	while (!libssh2_channel_eof(channel)) {
		ssize_t read_count =
			libssh2_channel_read(channel, r_buf, r_buf_size);

		if (read_count < 0)
			fprintf(stderr, "Unable to read response: %ld\n",
				read_count);
		else {
			fwrite(r_buf, 1, (size_t)read_count, stdout);
		}

		// Не читать ввод пользователя, пока не завершится вывод
		if (read_count == r_buf_size)
			continue;

		// Чтение stdin. Если EOF -- завершить цикл
		if (!fgets(w_buf, 98, stdin)) {
			libssh2_channel_send_eof(channel);
			break;
		}

		read_count =
			libssh2_channel_write(channel, w_buf, strlen(w_buf));

		if (read_count < 0)
			fprintf(stderr, "Unable to write w_buf: %ld\n",
				read_count);
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
		   int prog_argc,
		   char const ** prog_argv)
{
	/* Ответ сервера со способами аутентификации*/
	char * userauthlist = libssh2_userauth_list(session, username,
						    (uint32_t)strlen(username));
	if (!userauthlist)
		return 0;
	// Далее список есть

	// Установка флагов на основе списка выше и ключей программы
	int auth_pw = set_auth_way(prog_argc, prog_argv, userauthlist);

	if (auth_pw & AUTH_PW_KEYBOARD_INTERACTIVE) {
		// Передача пароля в колбек через глобальную переменную
		g_password = get_password(prog_argc, prog_argv);
		if (!g_password)
			g_password = getpass("Пароль: ");

		if (libssh2_userauth_keyboard_interactive(session, username,
							  &kbd_callback)) {
			fprintf(stderr, "Авторизация посредством "
					"keyboard-interactive не удалась.\n");
			return -1;
		} else {
			fprintf(stderr, "Авторизация прошла успешно\n");
		}
	} else if (auth_pw & AUTH_PW_PASSWORD) {
		char const * passwd = get_password(prog_argc, prog_argv);
		if (!passwd) {
			fprintf(stderr, "Неправильный пароль!\n");
			return -1;
		}
		if (libssh2_userauth_password(session, username, passwd)) {
			fprintf(stderr, "Неправильный пароль!\n");
			return -1;
		} else {
			fprintf(stderr, "Авторизация прошла успешно\n");
		}
	} else if (auth_pw & AUTH_PW_PUBLICKEY) {
		// Домашний каталог, либо текущий
		char const * h = getenv("HOME");
		if (!h || !*h)
			h = ".";

		size_t fn1sz = strlen(h) + strlen(pubkey) + 2;
		size_t fn2sz = strlen(h) + strlen(privkey) + 2;

		char * fn1 = malloc(fn1sz + fn2sz);
		if (!fn1) {
			free(fn1);
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		char * fn2 = fn1 + fn1sz;

		snprintf(fn1, fn1sz, "%s/%s", h, pubkey);
		snprintf(fn2, fn2sz, "%s/%s", h, privkey);

		if (libssh2_userauth_publickey_fromfile(session, username, fn1,
							fn2, nullptr)) {
			fprintf(stderr,
				"Авторизация по publickey не удалась\n");
			free(fn1);
			return -1;
		} else {
			fprintf(stderr, "Авторизация прошла успешно\n");
		}
		free(fn1);
	} else {
		fprintf(stderr, "Нет подходящего способа авторизации.\n");
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
		// Установка стандартного порта
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

char const * get_username(int prog_argc, char const ** prog_argv)
{
	for (int i = 1; i < prog_argc; ++i) {
		if (!strncmp(prog_argv[i], USERNAME_KEY, strlen(USERNAME_KEY)))
			return (prog_argv[i]) + strlen(USERNAME_KEY);
	}

	return getenv("USER");
}

char const * get_password(int prog_argc, char const ** prog_argv)
{
	for (int i = 1; i < prog_argc; ++i) {
		if (!strncmp(prog_argv[i], AUTH_PASSWORD_KEY,
			     strlen(AUTH_PASSWORD_KEY))) {
			return (prog_argv[i]) + strlen(AUTH_PASSWORD_KEY);
		}
		if (!strncmp(prog_argv[i], AUTH_PASSWORD_INTERACTIVE_KEY,
			     strlen(AUTH_PASSWORD_INTERACTIVE_KEY))) {
			return getpass("Пароль: ");
		}
	}
	return nullptr;
}

int get_communication_type(int prog_argc, char const ** prog_argv)
{
	int i;
	for (i = 1; i < prog_argc; ++i) {
		if (!strncmp(prog_argv[i], COMMAND_KEY, strlen(COMMAND_KEY)))
			break;
	}
	return (i == prog_argc) ? -1 : i;
}

char * combine_words(size_t count, char const ** words)
{
	size_t word_len = 0;
	for (size_t i = 0; i < count; ++i)
		word_len += strlen(words[i]) + 1;

	char * word = malloc(word_len);
	if (!word) {
		return nullptr;
	}
	word[0] = '\0';
	for (size_t i = 0; i < count; ++i) {
		strcat(word, words[i]);
		strcat(word, " ");
	}
	return word;
}

int communication_single_command(LIBSSH2_CHANNEL * channel,
				 int cmd_count,
				 char const ** cmds)
{
	assert(cmd_count >= 0);
	char * cmd = combine_words((size_t)cmd_count, cmds);
	if (!cmd) {
		fprintf(stderr, "Unable to allocate request command\n");
		return -1;
	}

	if (libssh2_channel_exec(channel, cmd)) {
		fprintf(stderr, "Unable to request command on channel\n");
		free(cmd);
		return -1;
	}

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
	}

	free(cmd);
	return 0;
}
