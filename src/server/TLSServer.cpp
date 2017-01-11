#include "TLSServer.h"

TLSServer::~TLSServer() {

    for (auto &th : handlerThreads) th.join();
    close(serverSock);
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

    SSL_CTX_set1_curves_list(ctx, "P-521:P-384");
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, TLSServer::clientVerifyCallback);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");

    loadCertificates(cacert, cert, key);

    memset(&sockInfo, 0, sizeof (sockaddr_in));
    serverSock = 0;

    sockInfo.sin_port = htons(port);
    sockInfo.sin_addr.s_addr = htonl(INADDR_ANY);
    sockInfo.sin_family = (AF_INET);
}

void TLSServer::recvConnections() {
    serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Setup socket
    if (serverSock < 0) {
        close(serverSock);
        throw "Error creating socket";
    }
    if (bind(serverSock, (struct sockaddr *) &sockInfo, sizeof (struct sockaddr_in)) < 0) { //Bind
        close(serverSock);
        throw "Error binding";
    }
    if (listen(serverSock, 10) < 0) { //Listen, max 10 clients in queue
        close(serverSock);
        throw "Error listening";
    }

    //Drop priviledges, setuid to nobody
    setuid(65534);
    while (!sig_int) { //While Ctrl+C not hit or SIG_INT raised...
        SSL *ssl;
        int hClientSock = 0;
        sockaddr_in clientInfo;
        socklen_t cliLen;

        cliLen = sizeof (clientInfo);
        memset(&clientInfo, 0, sizeof (sockaddr_in));

        hClientSock = accept(serverSock, (struct sockaddr*) &clientInfo, &cliLen); //Accept clients

        if (hClientSock < 0) {
            std::cerr << "Error on accept\n";
            close(hClientSock);
            continue; //Stop executing and go to next loop iteration
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            std::cerr << "Error creating new SSL\n";
            close(hClientSock);
            continue;
        }

        if (SSL_set_fd(ssl, hClientSock) != 1) {
            ERR_print_errors_fp(stderr);
            std::cerr << "Error creating SSL connection\n";
            close(hClientSock);
            continue;
        }

        int sslAcceptRet = SSL_accept(ssl);
        if (sslAcceptRet != 1) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(hClientSock);
            continue;
        }

        std::cout << "Got connection from: " << inet_ntoa(clientInfo.sin_addr) << " Using cipher " << SSL_get_cipher(ssl) << std::endl; //Print out connection info

        std::thread t1(&TLSServer::clientHandler, this, std::unique_ptr<TLSPeer>(new TLSPeer(SSL_get_peer_certificate(ssl), ssl, hClientSock, clientInfo, inet_ntoa(clientInfo.sin_addr))));
        handlerThreads.push_back(std::move(t1));
    }
}

inline void TLSServer::loadCertificates(const char* caCert, const char* srvCert, const char* srvKey) {
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

int TLSServer::clientVerifyCallback(int preVerify, X509_STORE_CTX* x509Ctx) {
    return preVerify;
}

void TLSServer::clientHandler(std::unique_ptr<TLSPeer> peer) {
    int recvBytes = 0;
    std::regex rand_cmd("^RAND\\s\\d{1,4}$");
    try {
        peer->sendData("HELO");
        do {
            std::string command = peer->recvData(&recvBytes);
            if (command.length() > 0) {
              std::cout << command;
              if (std::regex_match(command, rand_cmd)) { //Handle random command
                int randLen = atoi(command.substr(4, 4).c_str());
                std::cout << "Rand request for " << randLen << std::endl;
              }
            }

        } while (recvBytes > 0); //Do this loop until the client disconnects
        std::cout << "Client " << peer->ipAddr << " has disconnected." << std::endl;
    }
    catch (...) {
        ERR_print_errors_fp(stderr);
        std::cerr << "Critical error in R/W data to peer " << peer->ipAddr << std::endl;
    }
}
