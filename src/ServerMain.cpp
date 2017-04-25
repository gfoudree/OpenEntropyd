#include "TLSServer.h"
#include <csignal>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <functional>

#include "Logger.h"

std::shared_ptr<TLSServer> tls;
std::atomic<bool> sig_int;

void inline sigpipe_handler(int sig) {

}

void inline sig_handler(int sig) {
  sig_int = 1;
  tls->exit_handler(sig);
}

int main(int argc, char *argv[]) {

    int logFd = open(LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
    dup2(logFd, 2); //Redirect stderr to our logfile
    //dup2(logFd, 1); //Redirect stdout to our logfile

    //Handle SIGPIPE
    std::signal(SIGPIPE, sigpipe_handler);

    //Start TLS Server
    try {
        tls.reset(new TLSServer(true, "ca.crt", "server.crt", "server.key", 321, "0.0.0.0"));

        //Handle Ctrl+C / SIGINT so that our destructors are called.
        std::signal(SIGINT, sig_handler);
        std::signal(SIGTERM, sig_handler);

        Logger<const char*>::logToFile("Starting OpenEntropyd");
	      tls->recvConnections();
    } catch (const char *err) {
         Logger<const char*>::logToFile(err);
    } catch (...) {
        Logger<const char*>::logToFile("Critical error, exiting!");
    }
    close(logFd);
}
