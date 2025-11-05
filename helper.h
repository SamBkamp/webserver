#ifndef HELPER
#define HELPER
int open_connection(int *sockfd);
int parse_first_line(http_request *req, char* first_line);
int parse_http_request(http_request *req, char* data);
void free_http_request(http_request *req);
#endif
