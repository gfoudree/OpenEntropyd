#include "TLSServer.h"

int main() {
  TLSServer tls(8080, "PFSense-CA.crt", "OpenEntropyd.crt", "OpenEntropyd.key");
  tls.init();
}
