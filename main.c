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
  int sockfd, clients_connected = 0;
  struct pollfd clients[CLIENTS_MAX];
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];

  if(open_connection(&sockfd) != 0){
    perror("open_connection");
    return 1;
  }
  struct pollfd infd_poll_settings = {
    .fd = sockfd,
    .events = POLLIN | POLLOUT
  };


  while(1){
    if(clients_connected >= CLIENTS_MAX)
      continue;
    int ret_poll = poll(&infd_poll_settings, 1, 100);
    if(infd_poll_settings.revents & POLLIN > 0){
      clients[clients_connected].fd = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_size);
      clients[clients_connected].events = POLLIN | POLLOUT;
      clients_connected++;
      printf("client connected! [%d/%d]\n", clients_connected, CLIENTS_MAX);
    }
    //to prevent writing to the underlying var and messing up the loop
    int clients_connected_buff = clients_connected;
    for(int i = 0; i < clients_connected_buff; i++){
      int client_poll = poll(&clients[i], 1, 100);
      if((clients[i].revents & POLLIN) == 0)
	continue;
      ssize_t bytes_read = read(clients[i].fd, buffer, 1023);
      buffer[bytes_read] = 0;
      printf("%s", buffer);
      close(clients[i].fd);
      clients_connected--;
    }
  }
}
