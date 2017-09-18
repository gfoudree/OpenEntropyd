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

std::unique_ptr<unsigned char[]> TLSPeer::recvData(int *readLen) {
    std::unique_ptr<unsigned char[]> buf(new unsigned char[259]);
    memset(buf.get(), 0, sizeof(buf));
    *readLen = SSL_read(ssl, buf.get(), sizeof (buf) - 1);
    if (*readLen < 0) {
        throw std::string("Error reading from ").append(ipAddr).c_str();
    }
    return buf;
}

void TLSPeer::parseX509Cert() {
    if (cert != NULL) {
        certInfo.subj = std::make_unique<char *>(X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
        certInfo.issuer = std::make_unique<char *>(X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
    }
}

bool TLSPeer::sendData(const void *data, unsigned int len) {
  if (SSL_write(ssl, data, len) < 1) {
    ERR_print_errors_fp(stderr);
    Logger<const char*>::logToFile("Error writing data to server");
    return false;
  }
  return true;
}

bool TLSPeer::sendControlMsg(const unsigned int id) {
	proto p;
	p.data_id = id;
	return this->sendData((void*)&p, sizeof(proto));
}

