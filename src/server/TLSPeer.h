/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

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

typedef struct X509_Cert_Info {
    std::unique_ptr<char *> subj, issuer;
} X509_Cert_Info;

class TLSPeer {
private:
    X509 *cert;
    const char *ipAddr;
    SSL *ssl;
    int sock = 0;
    sockaddr_in cliInfo;
    
    void parseX509Cert();
public:
    X509_Cert_Info certInfo;
    
    void sendData(std::string data);
    std::string recvData(int *readLen);
    
    //friend std::ostream& operator<< (std::ostream &os, std::string data) {
        //TLSPeer::sendData(data);
    //}
    
    TLSPeer(X509 *cliCert, SSL *cliSsl, int cliSock, sockaddr_in cliAddr, const char *ip) : 
        cert(cliCert), ipAddr(ip), ssl(cliSsl), sock(cliSock), cliInfo(cliAddr)
    {
        parseX509Cert();
    };
    virtual ~TLSPeer();
};

#endif /* TLSPEER_H */

