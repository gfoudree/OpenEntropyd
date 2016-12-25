#include "TLSServer.h"
#include <signal.h>
#include <iostream>
#include <atomic>

std::atomic<bool> sig_int;

void inline sig_handler(int sig) {
  sig_int = true;
}

int main (int argc, char *argv[]) {

  //Handle Ctrl+C / SIGINT so that our destructors are called.
  sig_int = false;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sig_handler;
  sigfillset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);

  //Start TLS Server
  TLSServer tls(8080, "PFSense-CA.crt", "OpenEntropyd.crt", "OpenEntropyd.key");
  tls.init();
}
