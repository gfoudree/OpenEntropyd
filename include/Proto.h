#ifndef PROTO_H
#define PROTO_H

#define ID_GET_ENTROPY 1
#define ID_RECV_ENTROPY 2
#define SRV_HELO 0xFF
#define CLI_HELO 0xF0
#define PRIORITY0 0
#define PRIORITY1 1
#define PRIORITY2 2
#define PRIORITY3 3
#define PRIORITY4 4

#define PSK "TESTPSK" //TODO: Make this changed for production
#define HMAC_LEN 384/8

#include <openssl/hmac.h>
#include <memory>
#include <iostream>

struct proto {
  uint8_t data_id;                  //Type of request
  unsigned char data[306];          //Data block, cast to appropriate struct. 258 because entropy_reply = (1b+1b+256b+48b -> 306b);
};

struct entropy_request {
    uint8_t szEntropy;              //How much entropy are we requesting
    uint8_t priority;               //Priority of request (0-4)
    uint8_t id;                     //Unique ID of request
};

struct entropy_reply {
    uint8_t id;                     //Unique ID of request
    uint8_t szEntropy;              //How much entropy we got
    unsigned char entropyBuf[256];  //Actual entropy
    unsigned char HMAC[HMAC_LEN];
};

class Proto {

public:
	static bool verifyHMAC(struct entropy_reply er);
	static std::unique_ptr <unsigned char[]> genHMAC(struct entropy_reply er);
};

#endif
