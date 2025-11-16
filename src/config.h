//some config info for easy incorporations. Will be replaced with a proper on-disk runtime config.. eventually...
#ifndef PWS_CONFIG
#define PWS_CONFIG

#define PRIVATE_KEY_FILE "certs/priv.pem"
#define CERTIFICATE_FILE "certs/cert.pem"
//#define FULLCHAIN_FILE "certs/fullchain.pem"

#define HOST_NAME "fish"
#define HOST_NAME_LEN sizeof(HOST_NAME) //i think string literals in preprocessor definitions are char arrays and sizeof is computed at compile time but im not 100% sure on cross-compatibility
#define DOCUMENT_ROOT "data"
#endif
