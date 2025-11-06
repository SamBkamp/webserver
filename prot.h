#ifndef MAIN_PROT
#define MAIN_PROT

#define HTTP_PORT 6060
#define HTTPS_PORT 443
#define PORT_IN_USE HTTPS_PORT
#define CLIENTS_MAX 10
#define QUEUE_LEN 10
#define POLL_TIMEOUT 100
#define METHOD_GET 1
#define METHOD_POST 2

typedef struct ll_node{
  int fd;
  SSL *cSSL;
  struct ll_node *next;
}ll_node;


typedef struct{
  char method[10];
  char *path;
  char *connection;
  char *host;
}http_request;

typedef struct{
  uint16_t response_code;
  char *response_code_text; //todo make this a hashmap
  char *content_type;
  size_t content_length;
  char *location;
  char *body;
}http_response;
#endif
