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

int main(int argc, char* argv[]){
  int sockfd, clients[CLIENTS_MAX], clients_connected = 0;
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];

  if(open_connection(&sockfd) != 0){
    perror("open_connection");
    return 1;
  }
  struct pollfd poll_settings = {
    .fd = sockfd,
    .events = POLLIN | POLLOUT
  };


  while(1){
    if(clients_connected >= CLIENTS_MAX)
      continue;
    int poll_ret = poll(&poll_settings, 1, 100);
    if(poll_ret & POLLIN > 0){
      clients[clients_connected] = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_size);
      clients_connected++;
      printf("client connected! [%d/%d]\n", clients_connected, CLIENTS_MAX);
    }

    for(int i = 0; i < clients_connected; i++){
      ssize_t bytes_read = read(clients[i], buffer, 1023);
      buffer[bytes_read] = 0;
      printf("%s", buffer);
      close(clients[i]);
    }

  }
}
