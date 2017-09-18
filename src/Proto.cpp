#include "Proto.h"

bool Proto::verifyHMAC(struct entropy_reply &er) {
	if ((int)er.szEntropy > 256) {
		throw "The protocol is saying the entropy buffer is larger than the max size of 256 bytes!";
	}
	unsigned char *hmac = HMAC(EVP_sha384(), PSK, strlen(PSK), er.entropyBuf, er.szEntropy, NULL, NULL);
	if (memcmp(hmac, er.HMAC, HMAC_LEN) == 0) {
		return true;
	}
	else {
		return false;
	}
}

unsigned char *Proto::genHMAC(struct entropy_reply &er) {
	if ((int)er.szEntropy > 256) {
		throw "The protocol is saying the entropy buffer is larger than the max size of 256 bytes!";
	}
	unsigned char *hmac = HMAC(EVP_sha384(), PSK, strlen(PSK), er.entropyBuf, er.szEntropy, NULL, NULL);
	if (hmac == NULL) {
		throw "Error generating HMAC for entropy reply";
	}
}
