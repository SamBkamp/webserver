#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "prot.h"
#include "helper.h"

int send_http_response(SSL *cSSL, http_response *res){
  char buffer[1024];
  sprintf(buffer, "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length:%ld\r\n\r\n%s\r\n", res->response_code, res->response_code_text, res->content_length, res->body);  
  SSL_write(cSSL, buffer, strlen(buffer));
  free(res->response_code_text);
  return 0;
}

char *open_file(const char* path){
  int filefd = open(path, O_RDONLY);
  if(filefd < 0)
    return (char *)-1;
  return mmap(NULL, 4096, PROT_READ, MAP_SHARED, filefd, 0);
}

//TODO: don't pass random data variable to here. Create data structure
int populate_http_response(http_response *res, http_request *req, char* data){
  if(strcmp(req->path, "/") == 0){
    res->response_code = 200;
    res->response_code_text = malloc(3); //this is going to cause such a huge memory leak if ones not super careful
    res->content_type = NULL;
    res->content_length = strlen(data);
    res->body = data;
    strcpy(res->response_code_text, "OK");
  }else{
    res->response_code = 404;
    res->response_code_text = malloc(10);
    res->content_type = NULL;
    res->content_length = 0;
    res->body = NULL;
    strcpy(res->response_code_text, "NOT FOUND");
  }
  return 0;
}

void destroy_node(ll_node *node){
  close(node->fd);
  SSL_shutdown(node->cSSL);
  SSL_free(node->cSSL);
  free(node);
}


void setup_ssl_socket(ll_node *node){
  SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method()); //create new ssl context
  SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //using single diffie helman, I guess?
  int use_cert = SSL_CTX_use_certificate_file(sslctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM);
  int use_prv_key = SSL_CTX_use_PrivateKey_file(sslctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM);
  node->cSSL = SSL_new(sslctx);
  SSL_set_fd(node->cSSL, node->fd);
}

int main(){
  int sockfd, clients_connected = 0;
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];
  char *file_data = NULL;
  ll_node head = {
    .fd = 0,
    .next = NULL
  };
  ll_node *tail = &head;

  //load openSSL nonsense (algos and strings)
  OpenSSL_add_all_algorithms();  //surely this can be changed to load just the ones we want?
  SSL_load_error_strings();
  SSL_library_init();

  //open root file
  file_data = open_file("index.html");
  if(file_data == (char *)-1){
    perror("open_file");
    return 1;
  }

  if(open_connection(&sockfd) != 0){
    perror("open_connection");
    return 1;
  }
  printf("Server started on %d\n", PORT_IN_USE);


  //default poll settings, just add your fd
  struct pollfd poll_settings = {
    .fd = sockfd,
    .events = POLLIN | POLLOUT
  };

  while(1){
    if(clients_connected >= CLIENTS_MAX)
      continue;
    //check for new connections
    poll_settings.fd = sockfd;
    int ret_poll = poll(&poll_settings, 1, POLL_TIMEOUT);
    if((poll_settings.revents & POLLIN) > 0 && ret_poll >= 0){
      int ssl_err;
      char ip_string[16];
      ll_node *node = malloc(sizeof(ll_node));
      node->fd = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_size);
      setup_ssl_socket(node);
      ssl_err = SSL_accept(node->cSSL);
      if(ssl_err <= 0){
        printf("some freaking ssl error\n");
        destroy_node(node);
        continue;
      }
      node->next = NULL;
      tail->next = node;
      tail = node;
      clients_connected++;
      printf("client %s connected! [%d/%d]\n", long_to_ip(ip_string, peer_addr.sin_addr.s_addr), clients_connected, CLIENTS_MAX);
    }

    //service existing connections
    ll_node *prev_buffer = &head;
    for(ll_node *buf = head.next; buf != NULL; prev_buffer = buf, buf = buf->next){
      //poll socket
      int client_poll, bytes_read;
      http_request req = {0};
      http_response res = {0};
      poll_settings.fd = buf->fd;
      client_poll = poll(&poll_settings, 1, POLL_TIMEOUT);
      if((poll_settings.revents & POLLIN) == 0 || client_poll < 0)
        continue;

      //read and process data
      bytes_read = SSL_read(buf->cSSL, buffer, 1023);
      buffer[bytes_read] = 0;
      if(bytes_read == 0
         || parse_http_request(&req, buffer) < 0
         || req.path == NULL
         || req.host == NULL){
        printf("malformed query sent\n");
      }else{
        //create and send http response
        printf("method: %s | path: %s | host: %s\n", req.method, req.path, req.host);
        populate_http_response(&res, &req, file_data);
        send_http_response(buf->cSSL, &res);
      }

      //close connection and remove from LL
      prev_buffer->next = buf->next;
      if(prev_buffer->next == NULL)
        tail = prev_buffer; //if buf is tail move tail back too
      destroy_node(buf);
      free_http_request(&req);
      buf = prev_buffer;
      clients_connected--;
      printf("client disconnected! [%d/%d]\n", clients_connected, CLIENTS_MAX);
    }
  }
}
