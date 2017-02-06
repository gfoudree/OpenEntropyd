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
#include <atomic>
#include <thread>
#include <regex>

#include "TLSPeer.h"
#include "TLSSocket.h"

extern std::atomic<bool> sig_int;

class TLSServer : public TLSSocket {
protected:
    std::vector<std::thread> handlerThreads;
    void clientHandler(std::unique_ptr<TLSPeer> peer);

public:
    void recvConnections();
    TLSServer(bool isServer, const char *caCert, const char *cert, const char *key, unsigned int port, const char *host);
};

#endif
