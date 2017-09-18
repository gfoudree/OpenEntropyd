#include "Proto.h"


bool Proto::verifyHMAC(struct entropy_reply &er) {
	unsigned char *hmac = HMAC(EVP_sha384(), PSK, strlen(PSK), er.entropyBuf, er.szEntropy, NULL, NULL);
	if (memcmp(hmac, er.HMAC, HMAC_LEN) == 0) {
		return true;
	}
	else {
		return false;
	}
}

unsigned char *Proto::genHMAC(struct entropy_reply &er) {
	return HMAC(EVP_sha384(), PSK, strlen(PSK), er.entropyBuf, er.szEntropy, NULL, NULL);
}
