#ifndef XCPENC_H
#define XCPENC_H

#include <openssl/evp.h>

#include "common.h"

#define bool 						short
#define FALSE						0
#define TRUE						1
#define STATUS_OK					0
#define STATUS_ERR					-1
#define MAX_FILE_PATH_LEN_BYTES 	(4096-1) 	//-1 is to account for the null character
#define MIN_UKEY_LEN				6
#define MAX_FILENAME_LEN_BYTES		255 
#define DEFAULT_KEY_LENGTH			16

#define DEBUG 				printf("Line = %d, Function :%s, File: %s\n",__LINE__,__FUNCTION__, __FILE__ );
#define ASSERT(cond)											\
		if(!(cond)) 											\
		{														\
			printf("ASSERT for condition %s failed\n", #cond);	\
			return STATUS_ERR;									\
		}														\
							
/*
 * Data Structure for storing the user input as read from
 * the command line. This will be used for validating and 
 * then it will be used to populate the user_data structure
 * which is finally passed to the system call.
 */
typedef struct user_ip_t
{
	char* input_fname;
	char* output_fname;
	char* key;
	int keylen;
	bool isencrypt;
	bool isdecrypt;
	bool iscopy;
#ifdef EXTRA_CREDIT
	unsigned int ed_usize;
	unsigned int ed_keylen;
	char* ed_alg;
#endif
}user_inp;

/*
 * Below are the list of Functions implemented in xpcenc.c
 * Add an entry here for any function implemented there
 */
int populate_syscall_args(user_inp * input);
int do_syscall(req_packet * req);
void display_help(void);
int validate_user_input(user_inp * input);

#endif

