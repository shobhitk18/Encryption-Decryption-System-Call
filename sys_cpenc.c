#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h> 

#include "common.h"

#define MAX_KEYLEN_SUPPORTED 	256
#define MAX_BUF_SIZE 		PAGE_SIZE
#define MD5_DIGEST_SIZE 	16
#define DEBUG_PRINT printk(KERN_DEBUG "Line: %d Function: %s\n",__LINE__, __FUNCTION__);
#define MAX_IV_SIZE			16

typedef struct _preamble
{
	char key_digest[MD5_DIGEST_SIZE];
#ifdef EXTRA_CREDIT
	char alg[MAX_ALG_NAME_LEN];
	unsigned long inode;
	unsigned long f_size;
	//char checksum[MD5_DIGEST_SIZE];
#endif
}preamble_t;


asmlinkage extern long (*sysptr)(void *arg);

static void* glocal_rd_buf = NULL;
static req_packet* greq_ptr = NULL;
static int partial_write = 0;

static void* get_rd_buf(void)
{
	if(glocal_rd_buf == NULL)
	{
		glocal_rd_buf = kmalloc(MAX_BUF_SIZE, GFP_KERNEL);
		if(!glocal_rd_buf)
			return ERR_PTR(ENOMEM);
	}
	return glocal_rd_buf;
}

static req_packet*  get_req_packet(void)
{
	if(greq_ptr == NULL)
	{
		greq_ptr = kmalloc(sizeof(req_packet), GFP_KERNEL);
		if(greq_ptr == NULL)
			return ERR_PTR(ENOMEM);
		
		/* Initialize the memory to null values */
		greq_ptr->infile = NULL;
		greq_ptr->ofile = NULL;
		greq_ptr->keybuf = NULL;
		greq_ptr->keylen = 0;
		greq_ptr->flags = 0;
#ifdef EXTRA_CREDIT
		greq_ptr->crypt_alg = NULL;
		greq_ptr->crypt_usize = 0;
#endif
	}
	return greq_ptr;
}

/* 
 * These are some helper API to print the contents of the populated 
 * req structure or internal data/buffers
 */

/* Helper : Prints kernel buffer in ASCI format */
#ifdef MYDEBUG
static void print_buf_asci(char* buf, unsigned int len)
{
	int i = 0;
	printk("Buffer Length = %d\n", len);	
	for(i = 0; i < len; i++)
		printk("%02x",((unsigned char*)buf)[i]);
	printk("End Buffer Printing\n");
}

static void print_req(void)
{
	req_packet * req = get_req_packet();
	if(IS_ERR(req))
	{	
		printk(KERN_WARNING "No Memory allocated to req_packet\n");
		return;
	}

    printk("REQ::Input File = %s\n", req->infile);
    printk("REQ::Output File = %s\n", req->ofile);
	printk("REQ::Flags = %x\n", req->flags);
	printk("REQ::Keylength = %d\n", req->keylen);
	if(req->keylen > 0)
		print_buf_asci(req->keybuf, req->keylen);
#ifdef EXTRA_CREDIT
	printk("REQ::Crypto Algo = %s\n", req->crypt_alg);
    printk("REQ::Crypto Unit Size = %d\n", req->crypt_usize);	
#endif
	return;
}
#endif //endif MYDEBUG

/* API to validate input arguments*/
static int validate_args(void)
{
	int ret = 0;
	req_packet* req = get_req_packet();
	
	/* Check for flags to have single operation set */
	if(req->flags != 1 && req->flags != 2 && req->flags != 4)
	{
		printk(KERN_DEBUG "Flag is set for multiple operation.\n");
		ret = -1;
		goto out;
	}
	
	/* Check for _keylen and _key_buf argument to be NULL in case of copy operation */ 
	if(req->flags == 4 && (req->keylen != 0 || req->keybuf != NULL))
	{	
		printk(KERN_DEBUG "Key buffer/key length passed by user is not NULL for COPY operation.\n");
		ret = -1;
		goto out;
	}

	/* Check for _keylen and _key_buf argument to be non NULL in case of Encr/Decr operation */
	if(req->flags != 4 && (req->keylen == 0 || req->keybuf == NULL))
	{
		printk(KERN_DEBUG "Key buffer/key length is NULL for encr or decryp operation.\n");
		ret = -1;
		goto out;
	}
	/* File names should not be NULL. If Yes, return immediately*/
	if(req->infile == NULL || req->ofile == NULL)
	{
		printk(KERN_DEBUG "One or both the file names provided is NULL.\n");
		ret = -1;
		goto out;
	}
	/* Put an upper bound on the key length */ 
	if(req->keylen > MAX_KEYLEN_SUPPORTED)
	{
		printk(KERN_DEBUG "Key length is too large\n");
		ret = -1;
		goto out;
	}

#ifdef EXTRA_CREDIT
	/* Extra check to verify if any invalid option passed for copy operation*/
	if(req->flags == 4 && (req->crypt_usize != 0 || req->crypt_alg != NULL))
	{
		printk(KERN_DEBUG "Wrong options passed by user for COPY operation.\n");
		ret = -1;
		goto out;
	}
#endif

out:
	return ret;
}

/* Main API to perform md5 hash operation. 
 */
struct sdesc {
	struct shash_desc shash;
	char ctx[];
};	

int do_md5_hash(const unsigned char* key, unsigned int keylen, unsigned char* digest)
{
	int ret=0, size=0;
	struct crypto_shash *tfm;
	struct sdesc *sdesc;
	char *alg_name = "md5";
	
	tfm = crypto_alloc_shash(alg_name, CRYPTO_ALG_TYPE_SHASH, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "can't alloc tfm struct %s\n", alg_name);
		ret = PTR_ERR(tfm);
		goto out;
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
	{
		printk("shash_desc alloc failed\n");
		ret = -ENOMEM;
		goto out;
	}
	sdesc->shash.tfm = tfm;
	sdesc->shash.flags = 0;

	ret = crypto_shash_digest(&sdesc->shash, key, keylen, digest);
	kfree(sdesc);
	crypto_free_shash(tfm);
out:
	return ret;
}


/* Struct and API to perform encrypt operation. 
 */
struct skcipher_def {
	struct scatterlist sg_in;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
};

/* Perform Encryption on kernel buffer using the key buffer provided.
 * Src: Parts of this API has been taken from crypto kernel documentation
 * Following is the link for the source:
 * https://www.kernel.org/doc/html/v4.20/crypto/api-samples.html
 */
static int encr_decr_buffer(const void * key, const int keylen, 
		void *src, unsigned int slen,
		const long unsigned inode,const long pagenum,
		const char* alg, unsigned int is_encr)
{
	int ret = 0, ivsize, blk_size;
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char* ivdata = NULL;

	skcipher = crypto_alloc_skcipher(alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(skcipher)) {
		printk(KERN_INFO "could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		printk(KERN_INFO "could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Set encrypt key with user provided key */
	if (crypto_skcipher_setkey(skcipher, key, keylen)) {
		printk(KERN_INFO "key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	
	ivsize = crypto_skcipher_ivsize(skcipher);
	blk_size = crypto_skcipher_blocksize(skcipher);
#ifdef EXTRA_CREDIT
	if(is_encr && (slen%blk_size) != 0)
		slen += blk_size - (slen%blk_size);
#endif
	/* IV will be fixed for now, Filling with dummy data for now. 
	 * Set IV for the current encryption algo. Should be same for encr and decr operation.  
	 */
	
	ivdata = (char*)kzalloc(MAX_IV_SIZE, GFP_KERNEL);
	memcpy(ivdata, (void*)(&pagenum), sizeof(pagenum));
	memcpy(ivdata+8, (void*)(&inode), sizeof(inode));

	sk.tfm = skcipher;
	sk.req = req;

	/* We encrypt one data block */
	sg_init_one(&sk.sg_in, src, slen);
	//sg_init_one(&sk.sg_out, dest, dlen);

	skcipher_request_set_crypt(req, &sk.sg_in, &sk.sg_in, slen, ivdata);
	
	/* encrypt/decrypt data */
	if(is_encr)
		ret = crypto_skcipher_encrypt(sk.req);
	else
		ret = crypto_skcipher_decrypt(sk.req);
#ifdef EXTRA_CREDIT
	if(is_encr && ret == 0)
		ret = slen;
#endif
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (ivdata)
		kfree(ivdata);

	return ret;
}

static int encr_decr_file(struct file *fd1, struct file* fd2, 
							req_packet* req, int is_encr)
{
	int ret = 0, i;
	
	/* MD5 bufffers. Should clean them on exit */
	void * key = NULL;
	char * digest = NULL;

	/* Encryption key buffer in user space */
	void * u_keybuf = req->keybuf;
	int keylen = req->keylen;
#ifdef EXTRA_CREDIT
	unsigned long inode = fd1->f_inode->i_ino;
#endif
	/* Read/Write Variables */
	ssize_t rd_off = 0;
	ssize_t wr_off = 0;
	ssize_t rd_bytes = 0; 
	ssize_t wr_bytes = 0;
	unsigned long pagenum = 0;
	loff_t len = 0, wr_len = 0, bytes_to_read = 0;
	loff_t size = 0;
	
	/* Preamble DS */
	int preamble_size = 0;
	preamble_t* preamble = NULL; //ToDo: free in end
	
	mm_segment_t old_fs;

	char* rdbuf = (char*)get_rd_buf();
	if(!rdbuf )
	{
		ret = -ENOMEM;
		goto out;
	}
	
	bytes_to_read = size = i_size_read(fd1->f_inode);
	
	/* Verify and copy the key buffer provided by user */
	if(!access_ok(verify_read, u_keybuf, keylen))
	{
		printk(KERN_INFO "cannot access keybuf in user structure\n");
		ret = -EFAULT;
		goto out;
	}

	key = kmalloc(keylen, GFP_KERNEL);
	if(!key)
	{
		ret = -ENOMEM;
		goto out;
	}

	if(copy_from_user(key, u_keybuf, keylen))
	{
		printk(KERN_INFO "copy of keybuf from user space to kernel space failed. check permissions\n");  
		ret = -EFAULT;
		goto out;
	}
	
	preamble_size = sizeof(preamble_t); 
	preamble = kzalloc(preamble_size, GFP_KERNEL);
	printk("preamble_size = %d\n", preamble_size);

#ifdef EXTRA_CREDIT
	if(req->crypt_alg != NULL)
	{
		len = strncpy_from_user(preamble->alg, req->crypt_alg, sizeof(preamble->alg));
		if(len < 0)
		{
			ret = -EFAULT;
			goto out;
		}
	}
	else
		memcpy(preamble->alg, "ctr(aes)", sizeof(preamble->alg));

	if(is_encr)
	{	/* Adding inode no to the preamble */
		preamble->inode = inode;
		preamble->f_size = bytes_to_read;
	}
#endif 
	
	/* Find the hash of the input user key */
	//digest = (char*)kmalloc(MD5_DIGEST_SIZE, GFP_KERNEL);
	digest = preamble->key_digest;
	ret = do_md5_hash(key, keylen, digest);
	if(ret < 0)
	{
		printk(KERN_WARNING "Failed in md5\n");
		goto out;
	}

	old_fs = get_fs();
	set_fs(get_ds());

	if(is_encr)
	{
		/* Write the digest to the outfile as a preamble */
		len = vfs_write(fd2,(void*)preamble, preamble_size, &(fd2->f_pos));
		if(len != preamble_size)
		{
			partial_write = 1;
			printk("Failed writing the preamble to the output file \n");
			ret = -EIO;
			goto reset_fs;
		}
		wr_off += len;
	}
	else
	{
		/* Read the preamble from the file and verify with the digest */
		len = vfs_read(fd1, rdbuf, preamble_size, &(fd1->f_pos));
		if(len != preamble_size)
		{
			ret = -EIO;
			printk("Failed reading preamble from the encrypted file \n");
			goto reset_fs;
		}
		
		//Actual digest calculated from user key to be matched with what we get in rdbuf
		for(i = 0; i < MD5_DIGEST_SIZE; i++)
		{
			if(rdbuf[i] != digest[i])
			{
				printk(KERN_INFO "Key Mismatch!!\n");
				ret = -EACCES;
				goto reset_fs;
			}
		}
	
	#ifdef EXTRA_CREDIT
		if(0 != strncmp(preamble->alg, ((preamble_t *)rdbuf)->alg, sizeof(preamble->alg)))
		{
			printk("Wrong Cipher passed. Can't decrypt\n");
			ret = -EIO;
			goto reset_fs;
		}
	#endif

		memcpy(preamble, rdbuf, preamble_size);

	#ifdef EXTRA_CREDIT
		inode = preamble->inode;	
	#endif
		rd_off += len;
		printk(KERN_INFO "Key Matched!!\n");
	}

	/* Initialize Encryption module and start encrypting/decrypting data.
	 * Set lengths and offset correctly first */

	bytes_to_read -= rd_off;

	if(is_encr)		
		printk(KERN_DEBUG "Total bytes to encrypt: %lld\n", bytes_to_read);
	else
		printk(KERN_DEBUG "Total bytes to decrypt: %lld\n", bytes_to_read);
	
	while(bytes_to_read > 0)
	{
		len = bytes_to_read;
		if(len > MAX_BUF_SIZE)
			len = MAX_BUF_SIZE;

		/* Read the data into internal buffer */ 
		rd_bytes = vfs_read(fd1, rdbuf, len, &(fd1->f_pos));
		if(rd_bytes != len)
		{	
			printk(KERN_INFO "Failed reading data from file\n");
			ret = -EIO;
			break;
		}
		rd_off += rd_bytes;

		/* Encrypt/Decrypt the data read in rdbuf. Operation is specified in is_encr
		 * flag 
		 */
#ifdef EXTRA_CREDIT
		// Will use ret to get total bytes actually encrypted including padding
		ret = encr_decr_buffer(key, keylen, rdbuf, len, inode, pagenum, preamble->alg, is_encr);
#else
		ret =  encr_decr_buffer(key, keylen, rdbuf, len, 0xabcdabcd, 0xdeadbeef, "ctr(aes)", is_encr);
#endif
		if(ret < 0)
		{	
			printk(KERN_INFO "Failed in Encrypt/Decrypt Operation..Byte Offset: %ld\n",wr_off);
			break;
		}
		/* Now write the transformed data present in the internal buffer
		 * back to the output file passed by the user */
		
		wr_len = len;
#ifdef EXTRA_CREDIT
		if(is_encr)
		{
			if(ret != len)
			{
				wr_len += ret-len;
				printk(KERN_DEBUG "Pad Bytes: %lld\n",ret-len); 	
			}
			wr_bytes = vfs_write(fd2, rdbuf, wr_len, &(fd2->f_pos));
			ret = 0;
		}
		else
		{
			
			if(wr_len+wr_off > preamble->f_size)
				wr_len = preamble->f_size - wr_off;
			
			wr_bytes = vfs_write(fd2, rdbuf, wr_len, &(fd2->f_pos));
		}
#else
		wr_bytes = vfs_write(fd2, rdbuf, wr_len, &(fd2->f_pos));
#endif
		if(wr_bytes != wr_len)
		{	
			printk(KERN_INFO "Failed writing data to file\n");
			ret = -EIO;
			break;
		}
		wr_off += wr_bytes;

		bytes_to_read -= len;
		pagenum++;
	}

	if(bytes_to_read > 0 && wr_off > 0)
	{
		/* Partial write needs to be handled here */
		partial_write = 1;
		printk(KERN_INFO "Failed in between read/write.\n");
	}

reset_fs:
	set_fs(old_fs);

out:
	if(preamble)
		kfree(preamble);
	
	if(key)
		kfree(key);

	return ret;
}

/* Better to seperate it to avoid complex handling in single routine */
static int copy_file(struct file* fd1, struct file* fd2)
{
	/* By this time all checks have been done and we are certain all fields 
	 * all fields in the req struct_ are populated for the following operation
	 * and all file descriptors are populated
	 * */
	int ret = 0;
	char* buf = (char*)get_rd_buf();
	ssize_t tot_bytes_rd = 0;
	ssize_t tot_bytes_wr = 0;
	ssize_t rd_bytes = 0; 
	ssize_t wr_bytes = 0;
	loff_t len = 0, bytes_to_read = 0;
	loff_t size = 0;

	mm_segment_t old_fs;

	bytes_to_read = size = i_size_read(fd1->f_inode);
	printk(KERN_DEBUG "I/P File Size: %lld\n", bytes_to_read);
	
	old_fs = get_fs();
	set_fs(get_ds());

	while(bytes_to_read > 0)
	{
		len = bytes_to_read;
		if(bytes_to_read >= MAX_BUF_SIZE)
			len = MAX_BUF_SIZE;

		rd_bytes = vfs_read(fd1, buf, len, &(fd1->f_pos));
		tot_bytes_rd += rd_bytes;
		if(rd_bytes < 0 || rd_bytes != len)
		{
			printk(KERN_WARNING "Error Occured While reading data at byte offset %ld\n", tot_bytes_rd);	
			ret = rd_bytes;
			break;
		}
		wr_bytes = vfs_write(fd2, buf, rd_bytes, &(fd2->f_pos));
		tot_bytes_wr += wr_bytes;
			
		if(wr_bytes < 0 || wr_bytes != rd_bytes)
		{	
			printk(KERN_WARNING "Error Occured while writing data at byte offset %ld\n", tot_bytes_wr);	
			ret = wr_bytes;
			break;
		}
		
		bytes_to_read -= len;
	}
	
	set_fs(old_fs);  // Reset address limits back to original settings

	if(bytes_to_read > 0)
	{
		printk(KERN_WARNING "Should delete this output file and return back to the caller\n");   //ToDo: unlink
		partial_write = 1;
		ret = -EIO;
	}

	return ret;
}

/* This API should be called before returning back to user.
 * Cleans global buffers and state 
 */
void do_cleanup(void)
{
	if(glocal_rd_buf != NULL)
		kfree(glocal_rd_buf);
		
	if(greq_ptr != NULL)
		kfree(greq_ptr);

	glocal_rd_buf = NULL;
	greq_ptr = NULL;
	
}

/* Main Entry Point for the SYSCALL */
asmlinkage long cpenc(void *args)
{
	int ret = 0;
	umode_t mode = 0;
	struct filename* infile = NULL;
	struct filename* ofile = NULL;
	struct file *fd1, *fd2; 
	req_packet * req;	
	struct dentry *tmp = NULL;	

	printk("CPENC::cpenc received args %p \n", args);
	if (args == NULL)
	{
		ret = -EINVAL;
		goto out;
	}

	/* Implement some initial checks here */
	ret  = access_ok(VERIFY_READ, args, sizeof(req_packet));
	if(ret == 0)
	{
		printk(KERN_WARNING "Cannot access user structure\n");
		ret = -EFAULT;
		goto out;
	}
	
	/* Get req struct which is allocated once for the entire duration */
	req = get_req_packet();
	if(IS_ERR(req))
	{	
		printk(KERN_WARNING "No Memory allocated to req_packet\n");
		ret = PTR_ERR(req);
		goto out;
	}
	
	/*
	 * Copy User structure to kernel buffer.. Make sure we do a deep copy
	 * Copy user data to kernel internal buffer 
	*/
	
	if(copy_from_user(req, args, sizeof(req_packet)))
	{
		printk(KERN_WARNING "copy of args from user space to kernel space failed. Check permissions\n");  
		ret = -EFAULT;
		goto out;
	}
	
	ret = validate_args();
	if(ret != 0)
	{
		printk("Invalid arguments passed in request from user. Aborting..\n");
		ret = -EINVAL;
		goto out;
	}

	infile = getname(req->infile);
	if(IS_ERR(infile))
	{
		ret = PTR_ERR(infile);
		goto out;
	}
	req->infile = infile->name;
	
	ofile = getname(req->ofile);
	if(IS_ERR(ofile))
	{
		ret = PTR_ERR(ofile);
		goto out1;
	}
	req->ofile = ofile->name;	
	
	/* Open file for read and write..Its time to do some actual work */ 	
	fd1 = filp_open(req->infile, O_RDONLY, 0);
	if(!fd1 || IS_ERR(fd1))
	{
		ret = PTR_ERR(fd1);
		goto out2;
	}
	/* Check if input file is a directory */
	if(S_ISDIR(fd1->f_inode->i_mode)){
		ret = -EIO;
		printk(KERN_INFO "Input file can't be of DIR type\n");
		goto out2;
	}

	/* Setting minimum level privilidge for outfile based on permissions that current proc has on input file */
	mode = fd1->f_inode->i_mode;
	printk(KERN_DEBUG "Mode : %o\n",fd1->f_inode->i_mode);

	fd2 = filp_open(req->ofile, O_WRONLY|O_TRUNC|O_CREAT, mode);
	if(!fd2 || IS_ERR(fd2))
	{
		ret = PTR_ERR(fd2);
		goto out3;
	}
	/* Store dentry for output file to be used for clean up in case of partial writes */
	tmp = file_dentry(fd2);

	/*Check for same file as i/p and o/p */
	if(fd1->f_path.dentry->d_inode->i_ino == fd2->f_path.dentry->d_inode->i_ino)
	{
		printk(KERN_INFO "Input and Output Files can't be same\n");
		ret = -EINVAL;
		goto out3;
	}
	
	/* Execute User operation now */
	switch (req->flags)
	{
		case 1:
			ret = encr_decr_file(fd1, fd2, req, 1);
			break;
		case 2:
			ret = encr_decr_file(fd1, fd2, req, 0);
			break;
		case 4:
			ret = copy_file(fd1, fd2);
			break;
		default:
			printk("Code should never reach here..\n");
			break;
	}
	
	if(ret != 0)
		partial_write = 1;

	/* Do Cleanup before returning back to USER */
out3:
	if(fd1 && !IS_ERR(fd1))
		filp_close(fd1, NULL);
	
	if(fd2 && !IS_ERR(fd2))
		filp_close(fd2, NULL);
	
	if(partial_write)
	{
		inode_lock_nested(d_inode(tmp->d_parent), I_MUTEX_PARENT);
		vfs_unlink(d_inode(tmp->d_parent), tmp, NULL);
		inode_unlock(d_inode(tmp->d_parent));
		partial_write = 0;
	}
out2:
	putname(ofile);
out1: 
	putname(infile);
out:
	do_cleanup();
	return ret;
}


static int __init init_sys_cpenc(void)
{
	printk("installed new sys_cpenc module\n");
	if (sysptr == NULL)
		sysptr = cpenc;
	return 0;
}

static void  __exit exit_sys_cpenc(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cpenc module\n");
}

module_init(init_sys_cpenc);
module_exit(exit_sys_cpenc);
MODULE_LICENSE("GPL");
