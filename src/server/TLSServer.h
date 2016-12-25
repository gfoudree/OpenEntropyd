#ifndef TLS_SERVER
#define TLS_SERVER

#include <iostream>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <vector>

class TLSServer {
private:
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  EC_KEY *ecdh;
  sockaddr_in sockInfo;
  int serverSock = 0;

public:
  TLSServer(const unsigned int port, const char *cacert, const char *cert, const char *key);
  void init();
  ~TLSServer();

};
#endif