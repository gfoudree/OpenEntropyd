#include "TLSClient.h"
#include <iostream>

int main() {
  try {
    TLSClient tc(false, "ca.crt", "client.crt", "client.key", 321, "127.0.0.1");
    tc.secureConnect();
    tc.sendData("Hello!", 6);
  }
  catch (const char *err) {
      Logger::logToFile(err);
  } catch (...) {
      Logger::logToFile("Critical error, exiting");
  }
}
