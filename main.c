#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "prot.h"

int open_connection(int *sockfd){
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
  host_addr.sin_port = htons(HTTP_PORT); //host byte order (le) to network byte order (be)
  host_addr.sin_addr = (struct in_addr){INADDR_ANY};

  //bind address
  if(bind(*sockfd, (struct sockaddr *)&host_addr, sizeof(host_addr))!=0)
    return -1;


  //set socket to listening
  if(listen(*sockfd, QUEUE_LEN) != 0)
    return -1;
  return 0;
}

/*
  GET / HTTP/1.1
Host: fish:6060
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml;
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i
Pragma: no-cache
Cache-Control: no-cache

typedef struct{
  char method[10];
  char *path;
  char *connection;
  char *host;
}http_request;
*/
int parse_first_line(http_request *req, char* first_line){
  //method
  char *line_token = strtok(first_line, " ");
  if(line_token == NULL)
    return 1;
  strncpy(req->method, line_token, 10);
  //path
  line_token = strtok(NULL, " ");
  if(line_token == NULL)
    return 1;
  req->path = malloc(strlen(line_token)+1);
  strcpy(req->path, line_token);
  return 0;
}
int parse_http_request(http_request *req, char* data){
  char *token = strtok(data, "\r\n");
  if(token == NULL)
    return 1;
  //first line is different
  if(parse_first_line(req, token) != 0)
    return 1;
  //rest of the lines are normal
  return 0;
}

int send_http_response(int sockfd, http_response *res){
  char buffer[1024];
  sprintf(buffer, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length:%ld\r\n\r\n%s\r\n", res->content_length, res->body);
  write(sockfd, buffer, strlen(buffer));
  return 0;
}

int main(){
  char *hello_world = "<!doctype html><body><h1>Hello, world!</h1></body>";
  int sockfd, clients_connected = 0;
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];
  ll_node head = {
    .fd = 0,
    .next = NULL
  };
  ll_node *tail = &head;

  if(open_connection(&sockfd) != 0){
    perror("open_connection");
    return 1;
  }
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
    if((poll_settings.revents & POLLIN) > 0){
      ll_node *node = malloc(sizeof(ll_node));
      node->fd = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_size);
      node->next = NULL;
      tail->next = node;
      tail = node;
      clients_connected++;
      printf("client connected! [%d/%d]\n", clients_connected, CLIENTS_MAX);
    }

    //service existing connections
    ll_node *prev_buffer = &head;
    for(ll_node *buf = head.next; buf != NULL; prev_buffer = buf, buf = buf->next){

      //poll socket
      poll_settings.fd = buf->fd;
      int client_poll = poll(&poll_settings, 1, POLL_TIMEOUT);
      if(!(poll_settings.revents & POLLIN))
        continue;

      //read and process data
      http_request req;
      ssize_t bytes_read = read(buf->fd, buffer, 1023);
      buffer[bytes_read] = 0;
      //printf("%s", buffer);
      parse_http_request(&req, buffer);
      printf("method: %s | path: %s\n", req.method, req.path);
      http_response res = {
        .response_code = 200,
        .content_type = NULL,
        .content_length = strlen(hello_world),
        .body = hello_world
      };
      send_http_response(buf->fd, &res);

      //close connection and remove from LL
      close(buf->fd);
      prev_buffer->next = buf->next;
      if(prev_buffer->next == NULL)
        tail = prev_buffer; //if buf is tail move tail back too
      free(buf);
      buf = prev_buffer;
      clients_connected--;
      printf("client disconnected! [%d/%d]\n", clients_connected, CLIENTS_MAX);
    }
  }
}
