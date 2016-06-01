#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if defined _WIN32
	#include <sys/types.h>
	#include <winsock2.h>
	#include <ws2tcpip.h>

	#define ssize_t SSIZE_T
	#include <io.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netdb.h>

	#include <unistd.h>

	#define SOCKET int
	#define INVALID_SOCKET -1
#endif

#include <tls.h>

#if defined _WIN32
	#pragma comment(lib, "Ws2_32.lib")
	#if defined _WIN64
		#pragma comment(lib, "lib/x64/libtls-10.lib")
	#else
		#pragma comment(lib, "lib/x86/libtls-10.lib")
	#endif
#endif

// Global Constants
#define MAX_BUFFER            (1000)

// Basic Error Handling

#if !defined _WIN32
	#define WSACleanup()
        #define closesocket close
#endif

#define ECHOSERVER_ERROR(A)          fprintf(stderr, "ECHOSERVER: %s: %d (%s)\n", A, errno, strerror(errno)); WSACleanup(); exit(EXIT_FAILURE);
#define LIBTLS_NOCONTEXT_ERROR(A)    fprintf(stderr, "ECHOSERVER: LIBTLS: %s: %d (%s)\n", A, errno, strerror(errno)); WSACleanup(); exit(EXIT_FAILURE);
#define LIBTLS_CONTEXT_ERROR(A, B)   fprintf(stderr, "ECHOSERVER: LIBTLS: %s %s: %d (%s)\n", A, tls_error(B), errno, strerror(errno)); WSACleanup(); exit(EXIT_FAILURE);
#define LIBTLS_CONTEXT_WARN(A, B)   fprintf(stderr, "ECHOSERVER: LIBTLS: %s %s: %d (%s)\n", A, tls_error(B), errno, strerror(errno));

// This macro was renamed shortly after the api change we want to account for
#if defined TLS_READ_AGAIN
	#define tls_read(A, B, C) ({size_t __i__; tls_read(A, B, C, &__i__); (ssize_t)__i__;})
	#define tls_write(A, B, C) ({size_t __i__; tls_write(A, B, C, &__i__); (ssize_t)__i__;})
#endif

int main(int argc, char *argv[]) {
	#if defined _WIN32
	WORD w_version_requested;
	WSADATA wsa_data;
	int err;
	w_version_requested = MAKEWORD(2, 2);

	err = WSAStartup(w_version_requested, &wsa_data);
	if (err != 0) {
		printf("WSAStartup failed with error: %d\n", err);
		return 1;
	}
	#endif

	SOCKET    sock_listening;         // listening socket
	SOCKET    sock_connection;        // connection socket
	int       int_port;               // port number
	struct addrinfo hints, *res;      // socket stuff
	char      str_buffer[MAX_BUFFER] = { 0 }; // character buffer
	char     *ptr_end;                // for strtol()

									  // Get port number from the command line
	if (argc == 2) {
		int_port = strtol(argv[1], &ptr_end, 0);
		if (*ptr_end) {
			ECHOSERVER_ERROR("Invalid port number");
		}

		// If no arguments were given, set to a default port
	} else if (argc < 2) {
		int_port = 1234;

	} else {
		ECHOSERVER_ERROR("Invalid arguments");
	}
	
	// Get the address info
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	char str_port[20];
	sprintf(str_port, "%d", int_port);
	if (getaddrinfo(NULL, str_port, &hints, &res) != 0) {
		ECHOSERVER_ERROR("getaddrinfo() failed");
	}

	// Create the socket
	sock_listening = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock_listening == INVALID_SOCKET) {
		ECHOSERVER_ERROR("socket() failed");
	}

	// Enable the socket to reuse the address
	char reuseaddr = 1;                // True
	if (setsockopt(sock_listening, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
		ECHOSERVER_ERROR("setsockopt() failed");
	}

	// Bind to the address
	if (bind(sock_listening, res->ai_addr, (int)res->ai_addrlen) == -1) {
		ECHOSERVER_ERROR("bind() failed");
	}

	// Listen
	if (listen(sock_listening, 128) == -1) {
		ECHOSERVER_ERROR("listen() failed");
	}

	//// Libtls stuff here

	//HERE BE DRAGONS
	//Maintainer: joseph
	//@@@@@@@@@@@@@@@@@@@@@**^^""~~~"^@@^*@*@@**@@@@@@@@@
	//@@@@@@@@@@@@@*^^'"~   , - ' '; ,@@b. '  -e@@@@@@@@@
	//@@@@@@@@*^"~      . '     . ' ,@@@@(  e@*@@@@@@@@@@
	//@@@@@^~         .       .   ' @@@@@@, ~^@@@@@@@@@@@
	//@@@~ ,e**@@*e,  ,e**e, .    ' '@@@@@@e,  "*@@@@@'^@
	//@',e@@@@@@@@@@ e@@@@@@       ' '*@@@@@@    @@@'   0
	//@@@@@@@@@@@@@@@@@@@@@',e,     ;  ~^*^'    ;^~   ' 0
	//@@@@@@@@@@@@@@@^""^@@e@@@   .'           ,'   .'  @
	//@@@@@@@@@@@@@@'    '@@@@@ '         ,  ,e'  .    ;@
	//@@@@@@@@@@@@@' ,&&,  ^@*'     ,  .  i^"@e, ,e@e  @@
	//@@@@@@@@@@@@' ,@@@@,          ;  ,& !,,@@@e@@@@ e@@
	//@@@@@,~*@@*' ,@@@@@@e,   ',   e^~^@,   ~'@@@@@@,@@@
	//@@@@@@, ~" ,e@@@@@@@@@*e*@*  ,@e  @@""@e,,@@@@@@@@@
	//@@@@@@@@ee@@@@@@@@@@@@@@@" ,e@' ,e@' e@@@@@@@@@@@@@
	//@@@@@@@@@@@@@@@@@@@@@@@@" ,@" ,e@@e,,@@@@@@@@@@@@@@
	//@@@@@@@@@@@@@@@@@@@@@@@~ ,@@@,,0@@@@@@@@@@@@@@@@@@@
	//@@@@@@@@@@@@@@@@@@@@@@@@,,@@@@@@@@@@@@@@@@@@@@@@@@@
	//"""""""""""""""""""""""""""""""""""""""""""""""""""

	// Initialize libtls
	tls_init();

	// Initialize a configuration context
	struct tls_config *tls_sun_config = tls_config_new();
	if (tls_sun_config == NULL) {
		LIBTLS_NOCONTEXT_ERROR("tls_config_new() failed");
	}

	// Set the certificate file in the configuration context
	if (tls_config_set_cert_file(tls_sun_config, "server.crt") != 0) {
		LIBTLS_NOCONTEXT_ERROR("tls_config_set_cert_file() failed");
	}

	// Set the key file in the configuration context
	if (tls_config_set_key_file(tls_sun_config, "server.key") != 0) {
		LIBTLS_NOCONTEXT_ERROR("tls_config_set_key_file() failed");
	}

	// Set the allowed ciphers in the configuration context
	if (tls_config_set_ciphers(tls_sun_config, "compat") != 0) {
		LIBTLS_NOCONTEXT_ERROR("tls_config_set_ciphers() failed");
	}

	// Create a server context
	struct tls *tls_sun_context = tls_server();
	if (tls_sun_context == NULL) {
		LIBTLS_CONTEXT_ERROR("tls_config_set_ciphers() failed", tls_sun_context);
	}

	// Attach the configuration context to the server context
	if (tls_configure(tls_sun_context, tls_sun_config) != 0) {
		LIBTLS_CONTEXT_ERROR("tls_configure() failed", tls_sun_context);
	}

	// Enter an infinite loop to respond to client requests and echo input
	struct tls *tls_sun_io_context;
	while (1) {
		// tls_accept_socket requires tls_sun_io_context to be set to null
		// HARK YE ONLOOKER: make sure you do this for every request,
		// if you don't set to null, the address from the previous request
		// will be sent to tls_accept_socket, and there will be an error
		tls_sun_io_context = NULL;

		// accept() waits for connection
		if ((sock_connection = accept(sock_listening, NULL, NULL)) < 0) {
			ECHOSERVER_ERROR("accept() failed");
		}

		// The tls accept command takes the socket you send and makes a tls I/O context out of it
		int int_status = tls_accept_socket(tls_sun_context, &tls_sun_io_context, (int)sock_connection);
		if (int_status != 0) {
			LIBTLS_CONTEXT_WARN("tls_accept_socket() failed", tls_sun_context);
			continue;
		}

		fprintf(stderr, "accepted a client\n");

		// Read from the socket
		ssize_t int_out_length;
		if ((int_out_length = tls_read(tls_sun_io_context, str_buffer, MAX_BUFFER - 1)) < 0) {
			LIBTLS_CONTEXT_WARN("tls_read() failed", tls_sun_io_context);
			continue;
		}

		fprintf(stderr, "%lu bytes read from client: >%s<\n", (u_long)int_out_length, str_buffer);

		// Write to the socket
		if (tls_write(tls_sun_io_context, str_buffer, int_out_length) < 0) {
			LIBTLS_CONTEXT_WARN("tls_write() failed", tls_sun_io_context);
			continue;
		}

		// Close the tls I/O context
		if (tls_close(tls_sun_io_context) != 0) {
			LIBTLS_CONTEXT_WARN("tls_close() failed", tls_sun_io_context);
			continue;
		}

		// Free the tls I/O context
		tls_free(tls_sun_io_context);

                // Close the connection socket
                if (closesocket(sock_connection) != 0) {
                        ECHOSERVER_ERROR("close() failed");
                }
	}
}

