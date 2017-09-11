#include "TLSServer.h"

TLSServer::TLSServer(bool isServer, const char *caCert, const char *cert, const char *key, unsigned int port, const char *host)
 : TLSSocket(isServer, caCert, cert, key, port, host)
{
  ep = new EntropyPool();
}

TLSServer::~TLSServer() {
  for (auto &th : handlerThreads) th.join();
  close(sock);
  delete ep;
}

void TLSServer::exit_handler(int signum) {
  for (auto &th : handlerThreads) th.join();
}

void TLSServer::recvConnections() {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Setup socket
    if (sock < 0) {
        close(sock);
        throw "Error creating socket";
    }
    if (bind(sock, (struct sockaddr *) &sockInfo, sizeof (struct sockaddr_in)) < 0) { //Bind
        close(sock);
        throw "Error binding";
    }
    if (listen(sock, 10) < 0) { //Listen, max 10 clients in queue
        close(sock);
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

        hClientSock = accept(sock, (struct sockaddr*) &clientInfo, &cliLen); //Accept clients

        if (hClientSock < 0) {
            Logger<const char*>::logToFile("Error on server accept");
            close(hClientSock);
            continue; //Stop executing and go to next loop iteration
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            Logger<const char*>::logToFile("Error creating new SSL object");
            close(hClientSock);
            continue;
        }

        if (SSL_set_fd(ssl, hClientSock) != 1) {
            ERR_print_errors_fp(stderr);
            Logger<const char*>::logToFile("Error setting file descriptor for SSL object");
            close(hClientSock);
            continue;
        }

        int sslAcceptRet = SSL_accept(ssl);
        if (sslAcceptRet != 1) {
            ERR_print_errors_fp(stderr);
            Logger<const char*>::logToFile("Error accepting on SSL socket");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(hClientSock);
            continue;
        }

        Logger<std::string>::logToFile(std::string("Got connection from: ").append(inet_ntoa(clientInfo.sin_addr))
          .append(" Using cipher: ").append(SSL_get_cipher(ssl)));

        std::thread t1(&TLSServer::clientHandler, this, std::unique_ptr<TLSPeer>(new TLSPeer(SSL_get_peer_certificate(ssl), ssl, hClientSock, clientInfo, inet_ntoa(clientInfo.sin_addr))));
        handlerThreads.push_back(std::move(t1));
    }
}

void TLSServer::clientHandler(std::unique_ptr<TLSPeer> peer) {
    int recvBytes = 0;
    try {
        peer->sendData(SRV_HELO);
        do {
            proto p;
            auto data = peer->recvData(&recvBytes);
            memcpy(&p, data.get(), 258);
            if (p.data_id == ID_GET_ENTROPY) {
              entropy_request er;
              bzero(&er, sizeof(er));
              memcpy(&er, p.data, 3*sizeof(uint8_t));

              std::cout << "Got an Entropy Request for " << (int)er.szEntropy << " bytes\n";

              //Make the entropy Request
              entropy_queue eq;
              eq.priority = (int)er.priority;
              eq.size = (int)er.szEntropy;
              //std::promise<unsigned char*> hPromise;
              //std::future<unsigned char*> hFuture = hPromise.get_future();
              //ep->requestEntropy(eq);
              //hFuture.get();
            }
        } while (recvBytes > 0); //Do this loop until the client disconnects
        Logger<std::string>::logToFile(std::string("Client ").append(peer->ipAddr).append(" has disconnected"));
    }
    catch (const char *e) {
      ERR_print_errors_fp(stderr);
      Logger<const char*>::logToFile(e);
    }
    catch (...) {
        ERR_print_errors_fp(stderr);
        Logger<const char*>::logToFile(std::string("Critical error in R/W data to peer ").append(peer->ipAddr).c_str());
    }
}
