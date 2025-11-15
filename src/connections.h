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


int open_connection(int *sockfd, int port);
void check_unsec_connection(struct pollfd *poll_settings, struct sockaddr_in *peer);
int send_http_response(ll_node* connection, http_response *res);
#endif
