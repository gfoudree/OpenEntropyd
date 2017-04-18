#ifndef PROTO_H
#define PROTO_H

#define ID_GET_ENTROPY 1
#define ID_RECV_ENTROPY 2

struct proto {
  unsigned short data_id;

};

struct entropy_request {
    unsigned short entropy_ammt;
    unsigned short priority;
};

struct entropy_reply {
  unsigned int 
  unsigned char entropy_blob[512];
};

#endif
