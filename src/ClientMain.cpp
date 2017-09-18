#include "TLSClient.h"
#include "Proto.h"
#include <iostream>

int main() {
  try {
    TLSClient tc(false, "ca.crt", "client.crt", "client.key", 321, "127.0.0.1");
    tc.secureConnect();
    proto req;
    entropy_request er;

    bzero(&req, sizeof(req));
    er.szEntropy = 64;
    er.priority = 2;
    er.id = 3;
    req.data_id = ID_GET_ENTROPY;
    memcpy(req.data, &er, sizeof(er));
    tc.sendData(&req, sizeof(req));
  }
  catch (const char *err) {
      Logger<const char*>::logToFile(err);
  } catch (...) {
      Logger<const char*>::logToFile("Critical error, exiting");
  }
}
