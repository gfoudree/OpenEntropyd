#include "TLSClient.h"

TLSClient::TLSClient(bool isServer, const char *caCert, const char *cert, const char *key, unsigned int port, const char *host)
 : TLSSocket(isServer, caCert, cert, key, port, host)
{
}

TLSClient::~TLSClient() {
  close(sock);
  SSL_shutdown(ssl);
  SSL_free(ssl);
}

void TLSClient::secureConnect() {
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Setup socket
  if (sock < 0) {
      close(sock);
      throw "Error creating socket";
  }

  if (connect(sock, (struct sockaddr *)&sockInfo , sizeof(sockInfo)) < 0) {
    close(sock);
    throw "Error connecting to host";
  }

  ssl = SSL_new(ctx);
  if (ssl == NULL) {
      ERR_print_errors_fp(stderr);
      throw "Error creating new SSL";
      close(sock);
  }
  if (SSL_set_fd(ssl, sock) != 1) {
      ERR_print_errors_fp(stderr);
      throw "Error creating SSL connection";
      close(sock);
  }
  if (SSL_connect(ssl) != 1) {
      ERR_print_errors_fp(stderr);
      throw "Error creating SSL connection";
      close(sock);
  }
}

void TLSClient::sendData(const void *data, unsigned int len) {
  if (SSL_write(ssl, data, len) < 1) {
    ERR_print_errors_fp(stderr);
    Logger<const char*>::logToFile("Error writing data to server");
  }
}
