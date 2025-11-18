#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "config.h"
#include "prot.h"
#include "connections.h"
#include "string_manipulation.h"

char *connection_types[] = {"close", "keep-alive"};

//not all implemented (obviously)
char *one_hundreds[] = {"Continue", "Switching Protocols"};
char *two_hundreds[] = {"OK", "Created", "Accepted", 0, "No Content"};
char *three_hundreds[] = {0, "Moved Permanently", "Found", "See Other"};
char *four_hundreds[] = {"Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found"};
char *five_hundreds[] = {"Internal Server Error", "Not Implemented", "Bad Gateway"};
char **msd[] = {one_hundreds, two_hundreds, three_hundreds, four_hundreds, five_hundreds};


void destroy_node(ll_node *node){
  SSL_shutdown(node->cSSL);
  SSL_free(node->cSSL);
  close(node->fd);
  free(node);
}

//opens a bound listening connection on port port. sockfd is the address of the callers socket, returns 0 for no error
int open_connection(int *sockfd, int port){
  struct sockaddr_in host_addr;
  //init socket
  *sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(*sockfd < 0)
    return -1;

  //socket options
  if(setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0)
    perror("[NON-FATAL] couldn't set sockopt\n");

  //init address
  memset(&host_addr, 0, sizeof(struct sockaddr_in));
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = htons(port); //host byte order (le) to network byte order (be)
  host_addr.sin_addr = (struct in_addr){INADDR_ANY};

  //bind address
  if(bind(*sockfd, (struct sockaddr *)&host_addr, sizeof(host_addr))!=0)
    return -1;


  //set socket to listening
  if(listen(*sockfd, QUEUE_LEN) != 0)
    return -1;
  return 0;
}

void check_unsec_connection(struct pollfd *poll_settings){
  struct sockaddr_in peer;
  socklen_t peer_size = sizeof(peer);
  int ret_poll = poll(poll_settings, 1, POLL_TIMEOUT);
  if((poll_settings->revents & POLLIN) > 0 && ret_poll >= 0){
    int unsec_fd = accept(poll_settings->fd, (struct sockaddr*)&peer, &peer_size);
    char incoming_data[1024];
    http_request req = {0};
    read(unsec_fd, incoming_data, 1023);
    parse_first_line(&req, incoming_data);
    snprintf(incoming_data, 1024, "%s%s", HOST_NAME, req.path);
    ll_node connection = {
      .fd = unsec_fd,
      .cSSL = NULL,
      .next = NULL
    };
    http_response res = {
      .response_code = 301,
      .location = incoming_data
    };
    if(send_http_response(&connection, &res) < 0)
      perror("write");
    fputs(WARNING_PREPEND, stdout);
    puts(" unsecured connection dealt with");
    close(unsec_fd);
    return;
  }
}

int send_http_response(ll_node* connection, http_response *res){
  char buffer[1024];
  size_t bytes_written;
  //response category (ie. first digit of response code)
  int response_cat = res->response_code - (res->response_code % 100);
  switch (response_cat){
  case 300:
    bytes_written = sprintf(buffer, "HTTP/1.1 %d %s\r\nLocation: https://%s\r\nConnection: %s\r\n\r\n", res->response_code, msd[2][res->response_code-response_cat], res->location, connection_types[res->connection]);
    break;
  default:
    bytes_written = sprintf(buffer, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length:%ld\r\nConnection: %s\r\n\r\n%s\r\n", res->response_code, msd[(response_cat/100)-1][res->response_code-response_cat], res->content_type, res->content_length, connection_types[res->connection], res->body);
    break;
  }

  if(connection->cSSL != NULL)
    return SSL_write(connection->cSSL, buffer, bytes_written);
  else
    return write(connection->fd, buffer, bytes_written);
}

//handler function to accept new SSL connections and append them to the Lnked List
//returns 1 for new connection 0 for no new connection (so you can add it to a total)
int new_ssl_connections(struct pollfd *poll_settings, ll_node *tail, SSL_CTX *sslctx, int ssl_sockfd){
  poll_settings->fd = ssl_sockfd;
  int ret_poll = poll(poll_settings, 1, POLL_TIMEOUT);
  if((poll_settings->revents & POLLIN) > 0 && ret_poll >= 0){
    int ssl_err;
    ll_node *node = malloc(sizeof(ll_node));
    node->peer_addr = malloc(sizeof(struct sockaddr_in));
    node->peer_size = sizeof(struct sockaddr_in);
    node->fd = accept(ssl_sockfd, (struct sockaddr*)node->peer_addr, &node->peer_size);
    if(node->fd < 0){
      perror("accept");
      return 0;
    }
    node->cSSL = SSL_new(sslctx);
    SSL_set_fd(node->cSSL, node->fd);
    ssl_err = SSL_accept(node->cSSL);
    if(ssl_err <= 0){
      //i HATE openssl error handling
      fputs(SSL_ERROR_PREPEND, stdout);
      print_SSL_accept_err(SSL_get_error(node->cSSL, ssl_err));
      destroy_node(node);
      return 0;
    }
    node->requests = 0;
    node->conn_opened = time(NULL);
    node->next = NULL;
    tail->next = node;
    tail = node;
    return 1;
  }
  return 0;
}
