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

