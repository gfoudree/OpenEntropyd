/*
 * File:   TLSPeer.h
 * Author: gfoudree
 *
 * Created on December 25, 2016, 3:35 PM
 */

#ifndef TLSPEER_H
#define TLSPEER_H

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <memory>
#include <sstream>
#include "Logger.h"

typedef struct X509_Cert_Info {
    std::unique_ptr<char *> subj, issuer;
} X509_Cert_Info;

class TLSPeer {
public:
    X509 *cert;
    const char *ipAddr;
    SSL *ssl;
    int sock = 0;
    sockaddr_in cliInfo;
    X509_Cert_Info certInfo;

    void parseX509Cert();

    template <typename T> void sendData(const T &data) {
        std::stringstream ss;
        ss << data;

        int ret = SSL_write(ssl, ss.str().c_str(), ss.str().length());
        if (ret < 0) {
            ERR_print_errors_fp(stderr);
            throw std::string("Error writing data to ").append(ipAddr).c_str();
        }
    }

    std::unique_ptr<unsigned char[]> recvData(int *readLen);

    TLSPeer(X509 *cliCert, SSL *cliSsl, int cliSock, sockaddr_in cliAddr, const char *ip) :
        cert(cliCert), ipAddr(ip), ssl(cliSsl), sock(cliSock), cliInfo(cliAddr)
    {
        parseX509Cert();
    };
    virtual ~TLSPeer();
};

#endif /* TLSPEER_H */
