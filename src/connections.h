//to take care of inet connections, opening reading ports, writing etc etc
#ifndef PWS_CONNECTIONS
#define PWS_CONNECTIONS
extern char *connection_types[];
extern char *one_hundreds[];
extern char *two_hundreds[];
extern char *three_hundreds[];
extern char *four_hundreds[];
extern char *five_hundreds[];
extern char **msd[];


void destroy_node(ll_node *node);
int open_connection(int *sockfd, int port);
void check_unsec_connection(struct pollfd *poll_settings);
int send_http_response(ll_node* connection, http_response *res);
int new_ssl_connections(struct pollfd *poll_settings, ll_node *tail, SSL_CTX *sslctx, int ssl_sockfd);
#endif
