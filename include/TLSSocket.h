#ifndef TLSSOCKET_H
#define TLSSOCKET_H

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

class TLSSocket {
private:
  void loadCertificates(const char* caCert, const char* srvCert, const char* srvKey);
  static int clientVerifyCallback(int preVerify, X509_STORE_CTX *x509Ctx);

protected:
  SSL_CTX *ctx;
  const SSL_METHOD *method;
  sockaddr_in sockInfo;
  int sock;

public:
  TLSSocket(bool isServer, const char *caCert, const char *cert, const char *key, const unsigned int port, const char *host);
  ~TLSSocket();
};

#endif
