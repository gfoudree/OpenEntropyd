#ifndef PROTO_H
#define PROTO_H

#define ID_GET_ENTROPY 1
#define ID_RECV_ENTROPY 2
#define SRV_HELO 0xFF
#define CLI_HELO 0xF0

struct proto {
  uint8_t data_id;
  unsigned char data[258];
} _proto;

struct entropy_request {
    uint8_t szEntropy;
    uint8_t priority;
    uint8_t id;
} _entropy_request;

struct entropy_reply {
    uint8_t id;
    uint8_t szEntropy;
    unsigned char entropyBuf[256];
} _entropy_reply;

#endif
