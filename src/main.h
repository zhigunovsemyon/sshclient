#ifndef MAIN_H
#define MAIN_H
#include <libssh2.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Способ аутентификации
enum AUTH_PW {
	AUTH_PW_PASSWORD = 0b0001,
	AUTH_PW_KEYBOARD_INTERACTIVE = 0b0010,
	AUTH_PW_PUBLICKEY = 0b0100,
};


void usage(char const * prog_path);
void print_fingerprint(FILE *, char const * fingerprint);

int communication_cycle(LIBSSH2_CHANNEL *);
int get_communication_type(int prog_argc, char const ** prog_argv);
int communication_single_command(LIBSSH2_CHANNEL *,
				 int cmd_count,
				 char const ** cmds);

int set_destination(struct sockaddr_in * addr_to_set,
		    int prog_argc,
		    char const ** prog_argv);

int authentication(LIBSSH2_SESSION * session,
		   char const * username,
		   int prog_argc,
		   char const ** prog_argv);

char const * get_username(int prog_argc, char const ** prog_argv);
char const * get_password(int prog_argc, char const ** prog_argv);

static in_port_t const DEFAULT_PORT = 22;

static char const * const AUTH_PASSWORD_KEY = "-p=";
static char const * const AUTH_PASSWORD_INTERACTIVE_KEY = "-p";
static char const * const AUTH_PUBLICKEY_KEY = "-k";
static char const * const AUTH_INTERACTIVE_KEY = "-i";
static char const * const USERNAME_KEY = "-u=";
static char const * const COMMAND_KEY = "-c";

static char const * const pubkey = ".ssh/id_rsa.pub";
static char const * const privkey = ".ssh/id_rsa";

#endif // !MAIN_H
