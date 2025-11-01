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

#include "prot.h"
#include "helper.h"


void free_http_request(http_request *req){
  free(req->host);
  free(req->path);
}
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
  req->path = malloc(strlen(line_token)+1); //chars are 1 byte (almost always)
  strcpy(req->path, line_token);
  return 0;
}
int parse_http_request(http_request *req, char* data){
  char *token = strtok(data, "\r\n");
  size_t token_length = strlen(token);
  if(token == NULL)
    return 1;
  //first line is different
  if(parse_first_line(req, token) != 0)
    return 1;
  //rest of the lines are normal
  token = strtok(token+token_length+2, "\r\n");
  //this weird token+strlen math is to go to the next token of the original call to strtok in this function. parse_first_line makes a call to strtok on the substring passed to it and erasing its data of the first call, so we artificially add it back by passing the (untouched) rest of the string data.
  while(token != NULL){
    //printf("%s\n", token);
    if(strncmp(token, "Host", 4)==0){
      req->host = malloc(strlen((token+6))+1);
      strcpy(req->host, (token+6));
    }
    token = strtok(NULL, "\r\n");
  }
  return 0;
}

int send_http_response(int sockfd, http_response *res){
  char buffer[1024];
  sprintf(buffer, "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length:%ld\r\n\r\n%s\r\n", res->response_code, res->response_code_text, res->content_length, res->body);
  write(sockfd, buffer, strlen(buffer));
  return 0;
}

char *open_file(const char* path){
  int filefd = open(path, O_RDONLY);
  if(filefd < 0)
    return (char *)-1;
  return mmap(NULL, 4096, PROT_READ, MAP_SHARED, filefd, 0);
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
      parse_http_request(&req, buffer);
      printf("method: %s | path: %s | host: %s\n", req.method, req.path, req.host);

      http_response res = {
        .response_code = 200,
        .response_code_text = malloc(3),
        .content_type = NULL,
        .content_length = strlen(file_data),
        .body = file_data
      };
      strcpy(res.response_code_text, "OK");
      send_http_response(buf->fd, &res);

      //close connection and remove from LL
      close(buf->fd);
      free_http_request(&req);
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
