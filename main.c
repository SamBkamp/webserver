#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  if(*sockfd < 0){
    perror("socket");
    return -1;
  }

  //socket options
  if(setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) != 0)
    perror("[NON-FATAL] couldn't set sockopt\n");
  
  //init address
  memset(&host_addr, 0, sizeof(struct sockaddr_in));
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = htons(HTTP_PORT); //host byte order (le) to network byte order (be)
  host_addr.sin_addr = (struct in_addr){INADDR_ANY};

  //bind address
  if(bind(*sockfd, (struct sockaddr *)&host_addr, sizeof(host_addr))!=0){
    perror("bind");
    return -1;    
  }

  //set socket to listening
  if(listen(*sockfd, QUEUE_LEN) != 0){
    perror("listen");
    return -1;
  }
  return 0;
}

int main(int argc, char* argv[]){
  int sockfd;
  struct sockaddr_in peer_addr;
  socklen_t peer_size = sizeof(struct sockaddr_in);
  char buffer[1024];
  
  if(open_connection(&sockfd) != 0){
    return 1;
  }
  while(1){
    int peer_fd = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_size);

    ssize_t bytes_read = read(peer_fd, buffer, 1023);
    buffer[bytes_read] = 0;
    printf("%s\n", buffer);
    
    close(peer_fd);
  }
}
