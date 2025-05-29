/* chat_client_secure.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <ctype.h>

#define BUF_SIZE 1024
#define NAME_LEN 32
#define SHARED_SECRET "s3cr3tkey" // shared secret for HMAC

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

char *sanitize(char *msg) {
    for (int i = 0; msg[i]; i++) {
        if (!isprint(msg[i]) && msg[i] != '\n') msg[i] = '?';
    }
    return msg;
}

char *compute_hmac(const char *msg) {
    unsigned int len = 0;
    static char result[65];
    unsigned char *hmac = HMAC(EVP_sha256(), SHARED_SECRET, strlen(SHARED_SECRET), (unsigned char*)msg, strlen(msg), NULL, &len);
    for (int i = 0; i < len; i++) sprintf(&result[i*2], "%02x", hmac[i]);
    result[64] = 0;
    return result;
}

int verify_hmac(const char *msg, const char *recv_hmac) {
    char *computed = compute_hmac(msg);
    return strncmp(computed, recv_hmac, 64) == 0;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUF_SIZE];
    char username[NAME_LEN];
    int port;

    init_openssl();
    SSL_CTX *ctx = create_context();

    printf("Enter server port: ");
    if (scanf("%d", &port) != 1) exit(1);
    while (getchar() != '\n');

    printf("Enter your username: ");
    fgets(username, NAME_LEN, stdin);
    username[strcspn(username, "\n")] = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_write(ssl, username, strlen(username));

    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        int maxfd = sock > STDIN_FILENO ? sock : STDIN_FILENO;

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select error");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, BUF_SIZE, stdin) == NULL) break;
            sanitize(buffer);
            SSL_write(ssl, buffer, strlen(buffer));
        }

        if (FD_ISSET(sock, &readfds)) {
            int valread = SSL_read(ssl, buffer, BUF_SIZE - 1);
            if (valread <= 0) {
                printf("Connection closed by server.\n");
                break;
            }
            buffer[valread] = 0;

            // Extract HMAC if present
            char *sig_start = strstr(buffer, " [sig:");
            if (sig_start) {
                *sig_start = '\0';
                char recv_sig[65] = {0};
                sscanf(sig_start + 6, "%64[^]]", recv_sig);
                if (verify_hmac(buffer, recv_sig)) {
                    printf("%s\n", buffer);
                } else {
                    printf("[WARNING] Message integrity check failed!\n");
                }
            } else {
                printf("%s\n", buffer);
            }
        }
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

