#include "TLSSocket.h"

TLSSocket::~TLSSocket() {
  SSL_CTX_free(ctx); //Cleanup openSSL
  ERR_free_strings();
  EVP_cleanup();
}

TLSSocket::TLSSocket(bool isServer, const char *caCert, const char *cert, const char *key, const unsigned int port, const char *host) {
  OpenSSL_add_all_algorithms(); //Init OpenSSL and load error strings.
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  SSL_library_init();

  if (isServer)
    method = TLSv1_2_server_method(); //We want TLS 1.2
  else
    method = TLSv1_2_method();

  if (method == NULL) {
    ERR_print_errors_fp(stderr);
    throw "Error creating new SSL Method";
  }

  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
      ERR_print_errors_fp(stderr);
      throw "Error creating new SSL CTX";
  }

  SSL_CTX_set1_curves_list(ctx, "P-521:P-384");
  SSL_CTX_set_ecdh_auto(ctx, 1);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, TLSSocket::clientVerifyCallback);
  SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");

  loadCertificates(caCert, cert, key);

  memset(&sockInfo, 0, sizeof (sockaddr_in));
  sock = 0;

  //struct hostent *hostEntry = gethostbyname(host);
  sockInfo.sin_port = htons(port);
  sockInfo.sin_addr.s_addr = inet_addr(host);
  sockInfo.sin_family = (AF_INET);
}

inline void TLSSocket::loadCertificates(const char* caCert, const char* srvCert, const char* srvKey) {
    if (SSL_CTX_use_certificate_file(ctx, srvCert, SSL_FILETYPE_PEM) <= 0) { //Use certificate
        ERR_print_errors_fp(stderr);
        throw "Error using certificate file!";
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, srvKey, SSL_FILETYPE_PEM) <= 0) { //Use private key
        ERR_print_errors_fp(stderr);
        throw "Error using private key file!";
    }
    if (!SSL_CTX_check_private_key(ctx)) { //Do the private and public keys match?
        ERR_print_errors_fp(stderr);
        throw "Server private key error!";
    }
    if (SSL_CTX_load_verify_locations(ctx, caCert, NULL) != 1) { //Verification CA Cert
        ERR_print_errors_fp(stderr);
        throw "Error loading CA certificate";
    }

    SSL_CTX_set_verify_depth(ctx, 5);
}

int TLSSocket::clientVerifyCallback(int preVerify, X509_STORE_CTX* x509Ctx) {
    return preVerify;
}
