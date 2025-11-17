#ifndef MAIN_PROT
#define MAIN_PROT
#include <openssl/ssl.h>

#define HTTP_PORT 80
#define HTTPS_PORT 443
#define CLIENTS_MAX 10
#define QUEUE_LEN 10
#define POLL_TIMEOUT 100
#define METHOD_GET 1
#define METHOD_POST 2

#define CONNECTION_CLOSE 0
#define CONNECTION_KEEP_ALIVE 1

#define SSL_ERROR_PREPEND "\x1B[1;31m[SSL_ERROR]\x1B[0m"
#define ERROR_PREPEND "\x1B[1;31m[ERROR]\x1B[0m"
#define WARNING_PREPEND "\x1B[1;33m[WARN]\x1B[0m"

typedef struct ll_node{
  struct sockaddr_in *peer_addr;
  socklen_t peer_size;
  int fd;
  SSL *cSSL;
  struct ll_node *next;
}ll_node;


typedef struct{
  char method[10];
  char *path;
  uint8_t connection;
  char *host;
}http_request;

typedef struct{
  uint16_t response_code;
  char *content_type;
  size_t content_length;
  char *location;
  char *body;
  uint8_t connection;
}http_response;

typedef struct{
  char *file_path;
  char *data;
}loaded_file;

typedef struct{
  loaded_file *loaded_files;
  loaded_file *not_found;
  loaded_file *internal_server_error;
}root_file_data;

#endif
