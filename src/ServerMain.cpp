#include "TLSServer.h"
#include <signal.h>
#include <iostream>
#include <atomic>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "Logger.h"

std::atomic<bool> sig_int;

void inline sig_handler(int sig) {
    sig_int = true;
}

void inline sigpipe_handler(int sig) {

}

int main(int argc, char *argv[]) {

    int logFd = open(LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
    dup2(logFd, 2); //Redirect stderr to our logfile
    //dup2(logFd, 1); //Redirect stdout to our logfile

    //Handle Ctrl+C / SIGINT so that our destructors are called.
    sig_int = false;
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = sig_handler;
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    //Handle SIGPIPE
    signal(SIGPIPE, sigpipe_handler);

    //Start TLS Server
    try {
        TLSServer tls(true, "ca.crt", "server.crt", "server.key", 321, "0.0.0.0");
        std::cout << "Starting OpenEntropyd" << std::endl;
	      tls.recvConnections();
    } catch (const char *err) {
        std::cerr << "Error: " << err << std::endl;
    } catch (...) {
        std::cerr << "Critical error, exiting\n";
    }
    close(logFd);
}
