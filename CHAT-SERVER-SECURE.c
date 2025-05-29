// chat_server_secure.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#define MAX_CLIENTS 10
#define BUF_SIZE 1024
#define NAME_LEN 32
#define SHARED_SECRET "s3cr3tkey"
#define MAX_MSGS_PER_5S 10

typedef struct {
    SSL *ssl;
    int sock;
    char username[NAME_LEN];
    time_t timestamps[MAX_MSGS_PER_5S];
    int timestamp_index;
} client_t;

client_t clients[MAX_CLIENTS];

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
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

void broadcast(char *msg, int sender_index) {
    char full_msg[BUF_SIZE + NAME_LEN + 128];
    snprintf(full_msg, sizeof(full_msg), "%s: %s", clients[sender_index].username, msg);
    sanitize(full_msg);

    char *hmac = compute_hmac(full_msg);
    strncat(full_msg, " [sig:", sizeof(full_msg) - strlen(full_msg) - 1);
    strncat(full_msg, hmac, sizeof(full_msg) - strlen(full_msg) - 1);
    strncat(full_msg, "]", sizeof(full_msg) - strlen(full_msg) - 1);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (i != sender_index && clients[i].sock > 0) {
            SSL_write(clients[i].ssl, full_msg, strlen(full_msg));
        }
    }
}

int check_rate_limit(client_t *client) {
    time_t now = time(NULL);
    int count = 0;
    for (int i = 0; i < MAX_MSGS_PER_5S; i++) {
        if (now - client->timestamps[i] <= 5) count++;
    }
    if (count >= MAX_MSGS_PER_5S) return 0;
    client->timestamps[client->timestamp_index] = now;
    client->timestamp_index = (client->timestamp_index + 1) % MAX_MSGS_PER_5S;
    return 1;
}

int main() {
    int server_sock, port;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    printf("Enter port to listen on: ");
    scanf("%d", &port);
    getchar();

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_sock, MAX_CLIENTS);

    fd_set readfds;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        int maxfd = server_sock;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].sock > 0) {
                FD_SET(clients[i].sock, &readfds);
                if (clients[i].sock > maxfd) maxfd = clients[i].sock;
            }
        }

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select error");
            break;
        }

        if (FD_ISSET(server_sock, &readfds)) {
            int new_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_sock);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(new_sock);
                SSL_free(ssl);
                continue;
            }

            char uname[NAME_LEN];
            int uname_len = SSL_read(ssl, uname, NAME_LEN - 1);
            if (uname_len <= 0) {
                SSL_free(ssl);
                close(new_sock);
                continue;
            }
            uname[uname_len] = '\0';

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].sock <= 0) {
                    clients[i].sock = new_sock;
                    clients[i].ssl = ssl;
                    strncpy(clients[i].username, sanitize(uname), NAME_LEN);
                    memset(clients[i].timestamps, 0, sizeof(clients[i].timestamps));
                    clients[i].timestamp_index = 0;
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].sock > 0 && FD_ISSET(clients[i].sock, &readfds)) {
                char buffer[BUF_SIZE];
                int valread = SSL_read(clients[i].ssl, buffer, BUF_SIZE - 1);
                if (valread <= 0) {
                    close(clients[i].sock);
                    SSL_free(clients[i].ssl);
                    clients[i].sock = 0;
                } else {
                    buffer[valread] = '\0';
                    if (check_rate_limit(&clients[i])) {
                        broadcast(buffer, i);
                    } else {
                        char *msg = "[Rate limit exceeded. Wait before sending more.]\n";
                        SSL_write(clients[i].ssl, msg, strlen(msg));
                    }
                }
            }
        }
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

