/* 
 * File:   TLSPeer.cpp
 * Author: gfoudree
 * 
 * Created on December 25, 2016, 3:35 PM
 */

#include "TLSPeer.h"

TLSPeer::~TLSPeer() {
    X509_free(cert);
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
}

void TLSPeer::sendData(std::string data) {
    int ret = SSL_write(ssl, data.c_str(), data.length());
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
        throw std::string("Error writing data to ").append(ipAddr);
    }
}

std::string TLSPeer::recvData(int *readLen) {
    char buf[512];
    memset(buf, 0, sizeof(buf));
    *readLen = SSL_read(ssl, buf, sizeof (buf) - 1);
    if (*readLen < 0) {
        ERR_print_errors_fp(stderr);
        throw std::string("Error reading from ").append(ipAddr);
    }
    return std::string(buf);
}

void TLSPeer::parseX509Cert() {
    if (cert != NULL) {
        certInfo.subj = std::make_unique<char *>(X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
        certInfo.issuer = std::make_unique<char *>(X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
    }
}