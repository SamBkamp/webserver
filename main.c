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

root_file_data files;

char *one_hundreds[] = {"Continue", "Switching Protocols"};
char *two_hundreds[] = {"OK", "Created", "Accepted", 0, "No Content"}; //not all implemented (obviously)
char *three_hundreds[] = {0, "Moved Permanently", "Found", "See Other"};
char *four_hundreds[] = {"Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found"};
char *five_hundreds[] = {"Internal Server Error", "Not Implemented", "Bad Gateway"};
char **msd[] = {one_hundreds, two_hundreds, three_hundreds, four_hundreds, five_hundreds};


//retpath should be strlen(document_root) + strlen(path) + 20
char *format_dirs(char *path, char *ret_path){
  char append[20], *offset;
  int dots;
  if(path[strlen(path)-1] == '/')
    sprintf(append, "index.html");
  else
    *append = 0;
  sprintf(ret_path,"%s%s%s", DOCUMENT_ROOT, path, append);

  dots = 0;
  offset = ret_path;
  while(*offset != 0){
    if(*offset == '.')
      dots++;
    else if(*offset == '/' && dots > 1){
      *ret_path = (char)-1;
      break;
    }else
      dots = 0;
    offset++;
  }
  return ret_path;
}

char *open_file(const char* path){
  int filefd = open(path, O_RDONLY);
  if(filefd < 0)
    return (char *)-1;
  char *retval = mmap(NULL, 4096, PROT_READ, MAP_SHARED, filefd, 0);
  close(filefd);
  return retval;
}

int send_http_response(SSL *cSSL, http_response *res){
  char buffer[1024];
  //response category (ie. first digit of response code)
  int response_cat = res->response_code - (res->response_code % 100);
  switch (response_cat){
  case 300:
    sprintf(buffer, "HTTP/1.1 %d %s\r\nLocation: https://%s\r\n", res->response_code, msd[2][res->response_code-response_cat], res->location);
    break;
  default:
    sprintf(buffer, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length:%ld\r\nConnection: close\r\n\r\n%s\r\n", res->response_code, msd[(response_cat/100)-1][res->response_code-response_cat], res->content_type, res->content_length, res->body);
    break;
  }

  return SSL_write(cSSL, buffer, strlen(buffer));
}

//takes a request struct and sends back appropriate data to client
int requests_handler(http_request *req, SSL *cSSL){
  http_response res = {0};
  //check if host is valid
  if(strncmp(req->host, HOST_NAME, HOST_NAME_LEN) != 0
     && strncmp(req->host+4, HOST_NAME, HOST_NAME_LEN) != 0){ //second condition is to check for www. connections (but currently accepts  first 4 chars lol) TODO: fix this
    res.response_code = 301;
    res.location = HOST_NAME;
    send_http_response(cSSL, &res);
    return 0;
  }
  //open file
  char file_path[sizeof(DOCUMENT_ROOT) + strlen(req->path) + 20];
  format_dirs(req->path, file_path);
  char *file_data = open_file(file_path);

  //file can't be opened for one reason or another
  if(file_data == (char *)-1 || *file_path == (char)-1){
    res.response_code = 404;
    res.body = files.not_found->data;
    res.content_length = strlen(res.body);
    res.content_type = "text/html";
    send_http_response(cSSL, &res);
    return 0;
  }
  //todo, do this with something simpler (and faster) than printf family
  char content_buffer[20];
  snprintf(content_buffer, 20, "text/%s", get_file_type(file_path));
  //if file is valid and openable
  res.response_code = 200;
  res.content_type = content_buffer;
  res.content_length = strlen(file_data);
  res.body = file_data;
  send_http_response(cSSL, &res);
  munmap(file_data, 4096);
  return 0;
}

void destroy_node(ll_node *node){
  SSL_shutdown(node->cSSL);
  SSL_free(node->cSSL);
  close(node->fd);
  free(node);
}

void load_default_files(){
  loaded_file *not_found_file = malloc(sizeof(loaded_file));
  not_found_file->data = open_file("default/not_found.html");
  not_found_file->file_path = malloc(strlen("default/not_found.html"));
  strcpy(not_found_file->file_path, "default/not_found.html");
  files.not_found = not_found_file;

  loaded_file *internal_server_error = malloc(sizeof(loaded_file));
  internal_server_error->data = open_file("default/internal_server_error.html");
  internal_server_error->file_path = malloc(strlen("default/internal_server_error.html"));
  strcpy(internal_server_error->file_path, "default/internal_server_error.html");
  files.not_found = not_found_file;

  files.loaded_files = NULL;
}

int main(){
  int sockfd, clients_connected = 0;
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];
  struct pollfd poll_settings = {   //default poll settings, just add your fd
    .events = POLLIN | POLLOUT
  };
  ll_node head = {
    .fd = 0,
    .next = NULL
  };
  ll_node *tail = &head;

  //load default files into memory
  //todo: add error checking and maybe also passing files by ref
  load_default_files();

  //load openSSL nonsense (algos and strings)
  OpenSSL_add_all_algorithms();  //surely this can be changed to load just the ones we want?
  SSL_load_error_strings();
  SSL_library_init();

  //set up SSL context for all connections
  SSL_CTX *sslctx = SSL_CTX_new(TLS_server_method()); //create new ssl context
  SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); //using single diffie helman, I guess?
  int use_cert = SSL_CTX_use_certificate_file(sslctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM);
  int use_prv_key = SSL_CTX_use_PrivateKey_file(sslctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM);

  //opens socket, binds to address and sets socket to listening
  if(open_connection(&sockfd) != 0){
    perror("open_connection");
    return 1;
  }
  printf("Server started on %d\n", PORT_IN_USE);

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
      node->cSSL = SSL_new(sslctx);
      SSL_set_fd(node->cSSL, node->fd);
      ssl_err = SSL_accept(node->cSSL);
      if(ssl_err <= 0){
        //i HATE openssl error handling
        fputs(SSL_ERROR_PREPEND, stdout);
        print_SSL_accept_err(SSL_get_error(node->cSSL, ssl_err));
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
      poll_settings.fd = buf->fd;
      client_poll = poll(&poll_settings, 1, POLL_TIMEOUT);
      if((poll_settings.revents & POLLIN) == 0 || client_poll < 0)
        continue;

      //read and process data
      bytes_read = SSL_read(buf->cSSL, buffer, 1023);
      buffer[bytes_read] = 0;
      if(parse_http_request(&req, buffer) < 0
         || req.path == NULL
         || req.host == NULL){
        printf("%s malformed query sent\nrequest: %s\n", WARNING_PREPEND, buffer);
      }else{
        //create and send http response
        printf("method: %s | path: %s | host: %s\n", req.method, req.path, req.host);
        requests_handler(&req, buf->cSSL);
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
  SSL_CTX_free(sslctx);
}
