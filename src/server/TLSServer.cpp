#include "TLSServer.h"

TLSServer::~TLSServer() {
  std::cout <<"Exiting";

  close(serverSock);
  EC_KEY_free(ecdh);
  SSL_CTX_free(ctx); //Cleanup openSSL
  ERR_free_strings();
  EVP_cleanup();
}

TLSServer::TLSServer(const unsigned int port, const char *cacert, const char *cert, const char *key) {
  OpenSSL_add_all_algorithms(); //Init OpenSSL and load error strings.
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  SSL_library_init();

  method = TLSv1_2_server_method(); //We want TLS 1.2
  ctx = SSL_CTX_new(method);

  if (ctx == NULL) {
      ERR_print_errors_fp(stderr);
      throw "Error creating new SSL CTX";
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) != 1) { //Verification CA Cert
      ERR_print_errors_fp(stderr);
      throw "Error loading CA certificate";
  }

  SSL_CTX_set_verify_depth(ctx, 4);

  SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256");

  ecdh = EC_KEY_new_by_curve_name(OBJ_txt2nid("secp521r1")); //Setup ephemerical key DH
  if (!ecdh) {
      ERR_print_errors_fp(stderr);
      throw "Error creating new EC curve";
  }
  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1) {
      ERR_print_errors_fp(stderr);
      throw "Error setting ECDH params";
  }

  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) { //Use certificate
      ERR_print_errors_fp(stderr);
      throw "Error using certificate file!";
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) { //Use private key
      ERR_print_errors_fp(stderr);
      throw "Error using private key file!";
  }
  if (!SSL_CTX_check_private_key(ctx)) { //Do the private and public keys match?
      ERR_print_errors_fp(stderr);
      throw "Server private key error!";
  }

  memset(&sockInfo, 0, sizeof(sockaddr_in));

  sockInfo.sin_port = htons(port);
  sockInfo.sin_addr.s_addr = htonl(INADDR_ANY);
  sockInfo.sin_family = (AF_INET);
}

void TLSServer::init() {
  serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Setup socket
  if (serverSock < 0) {
      close(serverSock);
      throw "Error creating socket";
  }

  if (bind(serverSock, (struct sockaddr *)&sockInfo, sizeof(struct sockaddr_in)) < 0) { //Bind
      close(serverSock);
      throw "Error binding";
  }

  if (listen(serverSock, 10) < 0) { //Listen, max 10 clients in queue
      close(serverSock);
      throw "Error listening";
  }
  while (!sig_int)
  {
      SSL *ssl;
      int hClientSock = 0;
      sockaddr_in clientInfo;
      socklen_t cliLen;

      cliLen = sizeof(clientInfo);
      memset(&clientInfo, 0, sizeof(sockaddr_in));

      hClientSock = accept(serverSock, (struct sockaddr*)&clientInfo, &cliLen); //Accept clients

      if (hClientSock < 0)
      {
          std::cerr << "Error on accept\n";
          close(hClientSock);
          continue; //Stop executing and go to next loop iteration
      }

      ssl = SSL_new(ctx);
      if (ssl == NULL){
          ERR_print_errors_fp(stderr);
          std::cerr << "Error creating new SSL\n";
          close(hClientSock);
          continue;
      }

      if (SSL_set_fd(ssl, hClientSock) != 1)
      {
          ERR_print_errors_fp(stderr);
          std::cerr << "Error creating SSL connection\n";
          close(hClientSock);
          continue;
      }

      int sslAcceptRet = SSL_accept(ssl);
      if (sslAcceptRet != 1)
      {
          ERR_print_errors_fp(stderr);
          std::cerr << std::to_string(SSL_get_error(ssl, sslAcceptRet)).c_str() << std::endl;
          SSL_shutdown(ssl);
          SSL_free(ssl);
          close(hClientSock);
          continue;
      }

      std::cout << "Got connection from: " << inet_ntoa(clientInfo.sin_addr) << " Using cipher " << SSL_get_cipher(ssl) << std::endl; //Print out connection info

      char buf[512];
      int recvBytes = 0;
      X509 *cliCert;
      const char *welcomeMsg = "Hello!\n";

      cliCert = SSL_get_peer_certificate(ssl); //Get the peer's certifiate so we can verify identity

      //Suppose you can do some CA checking here, make sure it was by our CA
      if (cliCert == NULL)
          printf("Client did not supply certificate\n");
      else {
          char *subj, *issuer;
          subj = X509_NAME_oneline(X509_get_subject_name(cliCert), 0, 0);
          issuer = X509_NAME_oneline(X509_get_issuer_name(cliCert), 0, 0);
          printf("Subject: %s\nIssuer: %s\n", subj, issuer); //Print out certificate info
          free(subj);
          free(issuer);
      }

      SSL_write(ssl, welcomeMsg, strlen(welcomeMsg)); //Send the hello message
      do {
          memset(buf, 0, sizeof(buf));
          recvBytes = SSL_read(ssl, buf, sizeof(buf) - 1);
          std::string data(buf);

          std::cout << data.c_str(); //Print out the data recieved

      }
      while(recvBytes > 0); //Do this loop until the client disconnects
      std::cout << "Client disconnected." << std::endl;
      X509_free(cliCert);
      SSL_shutdown(ssl);
      close(hClientSock);
      SSL_free(ssl);
    }

}
