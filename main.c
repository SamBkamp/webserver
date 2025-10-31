#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <poll.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#define HTTP_PORT 6060
#define HTTPS_PORT 443
#define QUEUE_LEN 5
#define CLIENTS_MAX 10
#define POLL_TIMEOUT 100


typedef struct ll_node{
  int fd;
  struct ll_node *next;
}ll_node;

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

void print_LL(ll_node *head){
  for(ll_node *buf = head; buf != NULL; buf = buf->next){
    printf("node: %d\n", buf->fd);
  }
}

int main(){
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
      poll_settings.fd = buf->fd;
      int client_poll = poll(&poll_settings, 1, POLL_TIMEOUT);
      if(!(poll_settings.revents & POLLIN))
        continue;
      ssize_t bytes_read = read(buf->fd, buffer, 1023);
      buffer[bytes_read] = 0;
      printf("%s", buffer);
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
