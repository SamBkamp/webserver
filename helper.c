#include <stdio.h>
#include <string.h>
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

//helper function that turns an SSL error code into text. I could use built-in SSL error functions but its so complex and requires like 7 different function calls. This is good enough.
void print_SSL_accept_err(int SSL_err){
  switch(SSL_err){
  case SSL_ERROR_ZERO_RETURN:
    printf("Connection close by peer: sent close_notify\n");
    break;
  case SSL_ERROR_WANT_READ:
    printf("Operation did not complete, can be retried later\n");
    break;
  case SSL_ERROR_SYSCALL:
    printf("Fatal I/O Error\n");
    break;
  case SSL_ERROR_SSL:
    printf("Fatal SSL Library Error (most likely protocol error)\n");
    break;
  default:
    printf("some freaking SSL error\n");
    break;
  }
}

//takes a file path and returns a substring with its file type (ie. the characters after the last '.')
//NON-DESTRUCTIVE
char *get_file_type(char* path){
  if(path == NULL)
    return (char *)-1;
  char *end = path + strlen(path)-1;

  while(end != path-1 && *end != '.')
    end--;
  return end+1;
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
//http parsing stuff

void free_http_request(http_request *req){
  if(req->host != NULL)
    free(req->host);
  if(req->path != NULL)
    free(req->path);
}

//parses the first line of a http request (ie. HTTP/1.1 GET /)
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

//parses the whole http request
int parse_http_request(http_request *req, char* data){
  size_t data_len = strlen(data);
  char *token = strtok(data, "\r\n");
  size_t token_length;
  if(token == NULL || *token == 0)
    return 1;
  token_length = strlen(token);
  //first line is different
  if(parse_first_line(req, token) != 0){
    free_http_request(req);
    return 1;
  }
  //rest of the lines are normal
  //make sure there is actually data after the end of our first token
  if(token_length+2 > data_len){
    free_http_request(req);
    return 1;
  }
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

//stolen from: https://github.com/SamBkamp/c-server/blob/main/main.c
char* long_to_ip(char* out, unsigned long IP){
  memset(out, 0, 16); //16 bytes max for an IP string (with nullptr)
  size_t out_idx = 0;
  for(size_t i = 0; i < 3; i++){
    out_idx += sprintf(&out[out_idx], "%d.", ((unsigned char*)&IP)[i]);
  }
  out_idx += sprintf(&out[out_idx], "%d", ((unsigned char*)&IP)[3]); //last digit has no trailing .
  return out;
}
//OPENS FOR READ ONLY
char *open_file(char *path){
  int filefd = open(path, O_RDONLY);
  if(filefd < 0)
    return (char *)-1;
  char *retval = mmap(NULL, 4096, PROT_READ, MAP_SHARED, filefd, 0);
  close(filefd);
  return retval;
}

