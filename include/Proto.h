#ifndef PROTO_H
#define PROTO_H

#define MIN_ENT_SZ 16
#define MAX_ENT_SZ 256

#define ID_GET_ENTROPY 1
#define ID_RECV_ENTROPY 2
#define ID_INVALID_REQUEST 3
#define ID_HELO 4
#define ID_BYE 5

#define PRIORITY0 0
#define PRIORITY1 1
#define PRIORITY2 2
#define PRIORITY3 3
#define PRIORITY4 4

#define PSK "TESTPSK" //TODO: Make this changed for production
#define HMAC_LEN 384/8
#define ERPKT 306

#include <openssl/hmac.h>
#include <memory>
#include <string.h>
#include <iostream>

struct proto {
  uint8_t data_id;                    //Type of request
  unsigned char data[ERPKT];          //Data block, cast to appropriate struct. 306 because entropy_reply = (1b+1b+256b+48b -> 306b);
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
	static bool verifyHMAC(struct entropy_reply &er);
	static unsigned char *genHMAC(struct entropy_reply &er);
};

#endif
