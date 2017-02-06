#ifndef TLSCLIENT_H
#define TLSCLIENT_H

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

class TLSClient {
private:
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  sockaddr_in sockInfo;
  int serverSock;
  
public:
  static int clientVerifyCallback(int preVerify, X509_STORE_CTX* x509Ctx);

  TLSClient(const char *cliCert, const char *cliKey, const char *caCert);
  ~TLSClient();
};

#endif
