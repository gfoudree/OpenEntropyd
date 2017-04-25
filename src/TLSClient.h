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

#include "TLSSocket.h"
#include "Logger.h"

class TLSClient : public TLSSocket {
protected:
  SSL *ssl;
public:
  void secureConnect();
  void sendData(const void *data, unsigned int len);
  TLSClient(bool isServer, const char *caCert, const char *cert, const char *key, unsigned int port, const char *host);
  ~TLSClient();
};

#endif
