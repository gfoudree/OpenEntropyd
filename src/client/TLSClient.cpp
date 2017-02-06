#include "TLSClient.h"

TLSClient::~TLSClient() {
  SSL_CTX_free(ctx);
  ERR_free_strings();
  EVP_cleanup();
}

TLSClient::TLSClient(const char *cliCert, const char *cliKey, const char *caCert) {
  OpenSSL_add_all_algorithms(); //Init OpenSSL and load error strings.
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  SSL_library_init();

  method = TLSv1_2_method();
  if (method == NULL) {
    ERR_print_errors_fp(stderr);
    throw "Error while creating SSL Method";
  }
  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    throw "Error while creating SSL Context";
  }
  SSL_CTX_set1_curves_list(ctx, "P-521:P-384");
  SSL_CTX_set_ecdh_auto(ctx, 1);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, TLSClient::clientVerifyCallback);
  SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");

  if (SSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM) <= 0) { //Use certificate
      ERR_print_errors_fp(stderr);
      throw "Error using certificate file!";
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM) <= 0) { //Use private key
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

  memset(&sockInfo, 0, sizeof (sockaddr_in));
}

int TLSClient::clientVerifyCallback(int preVerify, X509_STORE_CTX* x509Ctx) {
  return preVerify;
}
