#ifndef COMMON_H
#define COMMON_H

typedef struct req_packet_t
{
	const char *infile;
	const char *ofile;
	void *keybuf;
	unsigned int keylen;
	unsigned int  flags;
#ifdef EXTRA_CREDIT
	unsigned int crypt_usize;
	char* crypt_alg;
#endif
}req_packet;

#ifdef EXTRA_CREDIT
#define MAX_ALG_NAME_LEN 	32
#endif

#endif
