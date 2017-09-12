#include "Proto.h"


bool Proto::verifyHMAC(struct entropy_reply er) {

}

std::unique_ptr <unsigned char[]> Proto::genHMAC(struct entropy_reply er) {

	std::unique_ptr <unsigned char[], [](void *x){free(x);}> res;

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	HMAC_Init_ex(&ctx, PSK, strlen(PSK), EVP_sha384(), NULL);
	HMAC_Update(&ctx, er.entropyBuf, er.szEntropy);
	HMAC_Final(&ctx, res.get(), &len);
	HMAC_CTX_cleanup(&ctx);

	return res;
}
