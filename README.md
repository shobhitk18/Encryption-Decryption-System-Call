# Encyption-Decryption-System-Call
*********************************************************************
SRC FILES : xcpenc.c sys_cpenc.c (source for loadable kernel module) 
HEADERS : common.h xcpenc.h
CONFIG : Reduced .config 
MAKE : Makefile
EXECUTABLE : xcpenc

******************************************************************
2.0 DESIGN FOR USER PROGRAM (xcpenc) W/O EXTRA_CREDIT
*******************************************************************

SRC FILES: xcpenc.c   
HEADERS: xcpenc.h , common.h   

xcpenc.c contains the main source code for the user level program which is responsible for parsing the command line options passed by the user. It supports the following options in the NON-EXTRA_CREDIT build.    

Options Supported:     
	-c --> Copy Operation   
	-e --> Encryption Operation    
	-d --> Decryption Operation    
	-p --> User Password/Key       
	-h --> display help/usage    

The options are parsed using getopt() and thus support parsing of options in any order. The program is well built to handle any erroneous inputs by the User on the CLI. For example the user may try to encrypt a file without passing -p flag which will be catched by the program and error will be returned back to the user. Another example could be passing -p "<passwd>" with -c which is a copy operation therefore there is no use of key and thus the program will return an error. Similarly many such test have been run and tested and some of them are provided in test scripts as well.More information regarding the tests can be found in the TEST/EVALUATION section later.

User program is also responsible for packaging the user arguments into a request structure which is defined in common.h as struct req_packet.This structure is shared between the user program and the sys_cpenc.ko (loadable kernel module described later) for passing argumnets from user space to kernel space. Following is the definition of the req_packet struct

typedef struct req_packet_t
{   
	const char *infile;    // pointer(in user space) to the string which contains the path of the input file passed by the user.    (Relative/Absolute)   
	const char *ofile;     // pointer(in user space) to the string which contains the path of the output file passed by the user. (Relative/Absolute)    
	void *keybuf;          // void pointer to the buffer is user space which contains the key passed by the user program to the kernel. This is the hashed key     
	unsigned int keylen;   // specifies the length of the key(hashed key) passed by the user program which will be used for encrypting the data    
	unsigned int  flags;   // primarily specifies the operation that needs to be performed by the system call.
#ifdef EXTRA_CREDIT
	unsigned int crypt_usize; // specifies the encryption unit size which the user provided. (FOR EXTRA_CREDIT ONLY) 
	char* crypt_alg;          // specifies the cipher algorithm specified by the user which is to be used for encryption. (FOR EXTRA_CREDIT ONLY)
#endif
}req_packet;

***********************************
2.1 Functions/Methods Description:
***********************************
main() : Entry Point.This function does two things, first it populates an internal struct based on the arguments provided by the user on CLI and then calls other methods for validating and executing the syscall on behalf of user   

validate_input_args() : This API validates the input arguments based on various checks. ex. user key should be more than 6 char etc.   
populate_req_packet() : This API converts the user key into a well defined keysize and finally populates the request packet to be sent in syscall(__NR_cpenc) hash_user_key() : This API will perform PKCS SHA1 hash for the _user key

*********************************************************
3.0 DESIGN FOR KERNEL MODULE (sys_cpenc) W/O EXTRA_CREDIT
*********************************************************

SRC FILES: sys_cpenc.c    
HEADERS: common.h    

HIGH LEVEL DESCRIPTION :-
This is the main program responsible for executing the newly added syscall(__NR_cpenc). There has been some code added in the kernel as well to support this new system call. This program runs in kernel space and is responsible for I/P validation, performing the required operation and sending the status back to user program
The program first copies the arguments from user space to kernel memory, performs all the validations on the input args and finally calls the respective methods for operations. The internal buffers are allocated globally so that we don't run out of memory in between the operation.
1.copy_file():   
	This method requests for an internal buffer of size PAGE_SIZE and reads the data from I/P file block by block and writes it to the output file. This also handles partial writes and handles them appropriately.   
2.encr_decr_file(is_encr , ...):   
	This method takes as input a flag to specify an encryption or decryption operation. Approch for both operations are explained seperately below:
 
 Encryption ==>Here I first hash the input key using MD5 and store it in the preamble. This preamble is then written onto the file at the very start. Then I request for an internal rdbuf of size PAGE_SIZE. I read the input file in chunks of 4K encrypt the buffer using ctr(aes) cipher and then write back the encrypted data into the output file. I have added checks for partially written file in which case it will be unlinked and user will be informed of the error.
	
  Decrytion ==> Here I first read the preamble data into my preamble struct. Then I compare the hash stored in the cipher file     with the hash obtained using the key passed by the user. If they match then we proceed ahead, else error is returned. I then read the encrypted data in chunks into my buffer, decrypt it and write it
into the output file.

**********************
3.1 DATA STRUCTURES:
***********************
1.
struct req_packet as described above (shared DS)
2.
typedef struct _preamble
{   
	char key_digest[MD5_DIGEST_SIZE];      // For storing the digest of the key passed by the user program   
#ifdef EXTRA_CREDIT
	char alg[MAX_ALG_NAME_LEN];            // For storing the cipher name (ONLY FOR EXTRA_CREDIT)   
	unsigned long inode;                   // For storing the inode number which will be used for initialising the first IV    (ONLY FOR EXTRA_CREDIT)    
	unsigned long f_size;                  // For storing the actual file size before encryption. Used for handling multiple ciphers/ blksize padding
#endif
}preamble_t;

***********************************
3.2 Functions/Methods Description:
***********************************
cpenc(): Main function called for the execution of the __NR_cpenc system call. Copies data from U-space to K-space opens files for operations.   

		validate_args(): This performs another round of   
		copy_file(): As Described above in 3.0
		encr_decr_file(): As Described above in 3.0
		encr_decr_buffer(): Perfomrs encryption/decryption on buffer of any length.

