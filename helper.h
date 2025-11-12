#ifndef HELPER
#define HELPER
int open_connection(int *sockfd, int port);
int parse_first_line(http_request *req, char* first_line);
int parse_http_request(http_request *req, char* data);
void free_http_request(http_request *req);
char* long_to_ip(char* out, unsigned long IP);
char *get_file_type(char* path);
void print_SSL_accept_err(int SSL_err);
char *open_file(char *path);
void send_plaintext_301(int sockfd);
#endif
