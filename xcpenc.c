#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#include "xcpenc.h"

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

#ifdef MYDEBUG
static void print_req(req_packet* req)
{
	int i;
	printf("------- struct req------\n"); 
	printf("Input File = %s\n", req->infile);
	printf("Output File = %s\n", req->ofile);
	printf("Flags = %x\n", req->flags);
	printf("Key length = %d\n", req->keylen);
	if(req->keylen > 0)
	for(i = 0; i < req->keylen; i++)
		printf("%02x\n", ((unsigned char*)req->keybuf)[i]);
#ifdef EXTRA_CREDIT
	printf("Crypto Unit Size = %d\n", req->crypt_usize);
	printf("Crypto Algo = %s\n", req->crypt_alg);
#endif
	return;
}
#endif

int hash_user_key(void* i_key, int i_keylen, unsigned char* o_key, int o_keylen)
{
	int ret = 0;
	const unsigned char salt[] = {'d','u','m','m','y'};
	
	if(PKCS5_PBKDF2_HMAC_SHA1(i_key, i_keylen, salt, sizeof(salt), 1, o_keylen, o_key) == 0 )
	{
		ret = -1;
		printf("Encryption of User key failed\n");
	}
	return ret; 
}

req_packet * populate_req_packet(user_inp* input)
{
	unsigned int len = 0;
	unsigned char* o_key = NULL;
	req_packet * req = (req_packet*) calloc(1,sizeof(req_packet));
	if(!req)
		return NULL;

	if(input->isencrypt)
		req->flags |= 1;
	if(input->isdecrypt)
		req->flags |= 2;
	if(input->iscopy)
		req->flags |= 4;
	
	req->infile = input->input_fname;
	req->ofile = input->output_fname;

	/* Should not populate keybuf for copy operation */
	if(req->flags & 4)
	{	
		req->keybuf = NULL;
		req->keylen = 0;
	}
	else
	{
		len = DEFAULT_KEY_LENGTH;
#ifdef EXTRA_CREDIT
		req->crypt_usize = input->ed_usize;
		req->crypt_alg = input->ed_alg;
		if(input->ed_keylen != 0)
			len = input->ed_keylen;
#endif
		o_key = (unsigned char*)malloc(sizeof(unsigned char)*len);
		int ret = hash_user_key(input->key, input->keylen, o_key, len);
		if(ret < 0)
		{
			free(o_key);
			free(req);
			req = NULL;
		}
		else
		{
			req->keybuf = o_key;
			req->keylen = len;
		}
	}

	return req;
}

/*
 * This API is a wrapper to make the syscall on 
 * behalf of the user program. 
 * Input : struct req_packet
 * Return 0 on SUCCESS
 * Return errno for ERROR
 */
int do_syscall(req_packet *req)
{
	int status = 0;
	void *packet = (void *)req;
  	//print_req(packet);	
	
	status = syscall(__NR_cpenc, packet);
	if (status == 0)
		printf("syscall returned %d\n", status);
	else
	{
		printf("syscall returned %d (errno=%d)\n", status, errno);
		status = errno;
	}
	return status;	
}

void display_help(void)
{
	printf("<USAGE>\n\t\t ./xcpenc -c <For Copy> -e <For Encrypt> -d <For Decrypt> -p <Key For Encryption/Decryption> \"INPUT FILE\" \"OUT FILE\"\n\n");
	printf("eg ./xcpenc -p \"this is my password\" -e infile outfile\n");
	printf("=>Options -c , -e and -d doesn't take any arguments\n");
	printf("=>Option -p takes user passphrase or key for encryption/decryption.Don't pass for copy \n");
	printf("=>Input File and Output File are MANDATORY ARGUMENTS\n");
	return;
}

int validate_input_args(user_inp * input)
{
	int ret = STATUS_OK;
	do
	{
		if( !(input->isencrypt || input->isdecrypt || input->iscopy) )
		{
			printf("ERROR::No Operation passed..Atleast one operation should be specified\n");
			ret = STATUS_ERR;
			break;
		}
		
		if((input->isencrypt && input->isdecrypt) || (input->isencrypt && input->iscopy) || 
				(input->isencrypt && input->iscopy))
		{
			printf("ERROR::More than one operation specified.\n");
			ret = STATUS_ERR;
			break;
		}

		if(input->iscopy)
		{	
			if(input->keylen != 0 || input->key != NULL)
			{	
				printf("ERROR::Key Should be NULL/0 if its a simple copy operation\n");
				ret = STATUS_ERR;
				break;
			}
#ifdef EXTRA_CREDIT
			if(input->ed_keylen != 0 || input->ed_usize != 0 || input->ed_alg != NULL)
			{
				printf("ERROR::Wrong options passed for a simple copy operation\n");
				ret = STATUS_ERR;
				break;
			}
#endif
		}

		if(input->iscopy != TRUE)
		{
			if(input->keylen < MIN_UKEY_LEN)
			{
				printf("ERROR::User passed a key of length: %d, which is less than minimum length criteria for Encr/Decr operation\n",input->keylen);
				ret = STATUS_ERR;
				break;
			}
		}
		// Add any user level checks here as and when discovered...
	}while(0);

	return ret;
}

int main(int argc, char *argv[])
{
	
	int ret = STATUS_OK;;
	int opt, val;
	(void)val;	
	user_inp *input = (user_inp*)calloc(1,sizeof(user_inp));
	/*
	 * References: linux manual - getopt()
	 */
#ifdef EXTRA_CREDIT
	const char* valid_opt = ":edchp:C:l:u:";
#else
	const char* valid_opt = ":edchp:";
#endif

	while((opt = getopt(argc, argv, valid_opt)) != -1)
	{
		switch(opt)
		{
			/* Encrypt Operation */
			case 'e':
				input->isencrypt = TRUE;
				break;

			/* Decrypt Operation */
			case 'd':
				input->isdecrypt = TRUE;
				break;

			/* Passphrase or Key used for encryption/decryption */
			case 'p':
				; 
				/* Empty Statement to make Compiler happy */
				/* Limiting size of key to 4K for now. This key will be encrypted and passed to the kernel later */
				if(strlen(optarg) > 4096)
				{
					printf("ERROR::Length of key is greater than expected\n");
					return (STATUS_ERR);
				}	
				char * key = (char*) malloc(sizeof(char) * strlen(optarg)+1);
				input->key = key;
				input->keylen = strlen(optarg)+1;
				memcpy(input->key, optarg, input->keylen+1);
				break;
			
			/* Simple copy w/o encryption/decryption */
			case 'c':
				input->iscopy = TRUE;
				break;

			/* Help/ Usage Option */	
			case 'h':
				display_help();
				return (STATUS_OK);
#ifdef EXTRA_CREDIT
			case 'C':
				if(strlen(optarg) > MAX_ALG_NAME_LEN)
				{
					printf("ERROR::Length of algoname is greater than expected\n");
					return(STATUS_ERR);
				}	
				char * alg = (char*) malloc(sizeof(char) * strlen(optarg)+1);
				input->ed_alg = alg;
				memcpy(input->ed_alg, optarg, strlen(optarg)+1);
				break;
			case 'l':
				if(atoi(optarg) == 0)
				{	
					printf("ERROR::Keylen should be a valid number(bits)\n");
					return(STATUS_ERR);
				}
				else
				{	
					if(atoi(optarg)%8 != 0)
					{
						printf("ERROR::Keylen should be whole multiples of 8\n");
						return (STATUS_ERR);
					}
					input->ed_keylen = atoi(optarg)/8;
				}
				break;
			case 'u':
				val = atoi(optarg);
				if(val != 0)
					input->ed_usize = val;
				else
				{
					printf("EERROR::encryption Unit size should be a non zero number\n"); 
					return (STATUS_ERR);
				}
				break;
#endif
			default:
				if(opt == '?')
					printf("ERROR::Unknown option : %c passed\n",(char)optopt); 
				else if(opt == ':')	
					printf("ERROR::Missing Argument for option: %c\n",(char)optopt);

				return (STATUS_ERR);
		}
	}
	
	if(argc - optind > 2)
	{
		printf("ERROR::More arguments provided than required. Please see Usage\n");
		display_help();
		return (STATUS_ERR);
	}

	if(argc - optind < 2)	
	{
		printf("ERROR::File names missing.Please see Usage\n");
		display_help();
		return (STATUS_ERR);
	}
	
	int idx = optind;
	
	int len = strlen(argv[idx])+1;	
	input->input_fname = (char*) malloc(len+1);
	memcpy(input->input_fname, argv[idx], strlen(argv[idx])+1);	
	idx++;

	len = strlen(argv[idx])+1;
	input->output_fname = (char*) malloc(len);
	memcpy(input->output_fname,  argv[idx], strlen(argv[idx])+1);
	
	if(validate_input_args(input) == STATUS_OK)
	{
		req_packet * req = populate_req_packet(input);
		if(req != NULL)
		{	
			ret = do_syscall(req);
			free(req->keybuf);
		}
	}
	else
		ret = STATUS_ERR;
	
	
	if(input->key != NULL)
		free(input->key);

	free(input->input_fname);
	free(input->output_fname);
#ifdef EXTRA_CREDIT
	if(input->ed_alg)
		free(input->ed_alg);
#endif

	return (ret);
}
