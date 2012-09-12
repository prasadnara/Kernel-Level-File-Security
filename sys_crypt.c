#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/slab.h>		
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>


MODULE_LICENSE("GPL");

extern int (*mysyscall)(char *infile, char *outfile, void *keybuf, unsigned int keylen, unsigned int flags);

int khash(char *, int, char *);
int aes_encrypt(char *, unsigned int , void *, size_t);
int aes_decrypt(char *, unsigned int, void *, size_t);
int preamble_write(struct file *, char *, char *, int, int, int);
int preamble_check(struct file *, char *, char *, char *, int, int*);

int syscrypt(char *infile, char *outfile, void *keybuf, unsigned int keylen, unsigned int flags)
{

    struct file *filp_read;
    struct file *filp_write;
    void *read_buf=NULL;
    mm_segment_t oldfs;
    int bytes_read = 0;
    int bytes_write = 0;
    int check=0;
    int size=0;
    int ret=0;
    int pw_ret;        //preamble write check
    int pc_ret;	  //preamble read check
    int CIPHER_BLOCK_SIZE=16;
    int padding=0;
     unsigned int len = PAGE_CACHE_SIZE;
    char *chkbuf = NULL;
    char *buf=NULL;
    char *hash=kmalloc(keylen, GFP_KERNEL);
    umode_t mode_r;

   printk (KERN_ALERT "\n Infile is %s", infile);
    if(!hash)
    {
	ret = -ENOMEM; 
	goto exit;
    }
	
    buf=kmalloc(keylen,GFP_KERNEL);
    
    if(!buf)
    {
	ret = -ENOMEM; 
	goto  freehash;
    }

        
    if(copy_from_user(buf, keybuf, keylen))
    {
	ret = -EFAULT;
       goto freebuf;    	
    }
   
    
    read_buf=kmalloc(len,GFP_KERNEL);
    
    if(!read_buf)
    {
	ret = -ENOMEM;
	goto freebuf; 
    }

    chkbuf=kmalloc(CIPHER_BLOCK_SIZE,GFP_KERNEL);

    if(!chkbuf)
    {
	ret = -ENOMEM;
	goto freereadbuf; 
    }


    

    filp_read = filp_open(infile, O_RDONLY, 0);
    if (!filp_read || IS_ERR(filp_read)) {
	printk("wrapfs_read_file err %d\n", (int) PTR_ERR(filp_read));
       ret = -EIO; 
	goto freechkbuf; 
	  
    }
    
    if (!filp_read->f_op->read)
	{ret = -EIO; printk(KERN_ALERT "\n filp_read->f_op->read failed"); goto freechkbuf;} 

    mode_r = filp_read->f_dentry->d_inode->i_mode;
    filp_write = filp_open(outfile, O_CREAT | O_WRONLY | O_TRUNC, mode_r);
    if (!filp_write || IS_ERR(filp_write)) {
	printk("wrapfs_write_file err %d\n", (int) PTR_ERR(filp_write));
       ret = -EIO; 
	goto freechkbuf;  
    }

    if (!filp_write->f_op->write)
	{ret = -EIO; printk(KERN_ALERT "filp_write->f_op->write failed"); goto freechkbuf;}  

    filp_write->f_dentry->d_inode->i_uid= filp_read->f_dentry->d_inode->i_uid;
    filp_write->f_dentry->d_inode->i_gid= filp_read->f_dentry->d_inode->i_gid;
    /* now read len bytes from offset 0 */
    filp_read->f_pos = 0;		/* start offset */
    filp_write->f_pos = 0;
    oldfs = get_fs();
    set_fs(KERNEL_DS);

    
       size = filp_read->f_dentry->d_inode->i_size ;
       
	if((size%CIPHER_BLOCK_SIZE)!=0)
	    padding = CIPHER_BLOCK_SIZE - (size%CIPHER_BLOCK_SIZE);
    
    printk(KERN_ALERT "\n padding = %d", padding); 
    if( (flags & 0x01) != 0x01)	
    {
	pw_ret = preamble_write(filp_write, buf, hash, padding, keylen, bytes_write);
	if(pw_ret)
	{
	   
	   return -EINVAL;
	   goto freechkbuf;
	}

	while(true) 
       {
	  memset(read_buf, 0, len);
	  bytes_read = vfs_read(filp_read, read_buf, len, &filp_read->f_pos);
	  
	  if((bytes_read%CIPHER_BLOCK_SIZE)!=0)
	  {
		memset((read_buf+bytes_read),0,padding); //Pad the buffer to be multiple of 16
		bytes_read += padding;          //Update the bytes read from file
         }

	  check = aes_encrypt(buf, keylen, read_buf, (bytes_read));
	  
	  
	  if(check!=0)
	  {
           ret=-EINVAL;
           goto freechkbuf;       
         }
         
	  bytes_write = vfs_write(filp_write, read_buf, bytes_read, &filp_write->f_pos);
	  if(bytes_read < len)
             break;
       }
    }
    else
    {
	pc_ret=preamble_check(filp_read, buf, hash, chkbuf, keylen, &padding);
	if(pc_ret)
	{
		ret = -EINVAL;
		goto freechkbuf;
	}
	size = size - (keylen+sizeof(padding));
	while(true) 
       {
	  memset(read_buf, 0, len);
	  bytes_read = vfs_read(filp_read, read_buf, len, &filp_read->f_pos);
	  
	  check=aes_decrypt(buf, keylen, read_buf, bytes_read);
	  if(check<0)
		{ret = -EINVAL; goto freechkbuf;}

	  size = size - bytes_read;
	  if(size==0)
		bytes_read -= padding;
	 	
	  bytes_write = vfs_write(filp_write, read_buf, bytes_read, &filp_write->f_pos);
	  if(bytes_read < len)
             break;
       }
    }
   
    set_fs(oldfs);

    /*close files*/
    filp_close(filp_read, NULL);
    filp_close(filp_write, NULL);
    
freechkbuf:   
   kfree(chkbuf);
   
freereadbuf:
   kfree(read_buf); 

freebuf:
    kfree(buf);

freehash:
    kfree(hash);

exit:
    return ret;

}

//During encryption
int preamble_write(struct file *filp_write, char *buf, char *hash, int padding, int keylen, int bytes_write)
{
	int ret;
	char padstring[sizeof(int)];
       printk(KERN_ALERT "\n going to call khash");
       ret=khash(buf, keylen, hash);
	printk(KERN_ALERT "\n Just called khash");
	if(ret)
	{
	    goto exit;
	}
	memcpy(padstring, &padding, sizeof(int));
	bytes_write = vfs_write(filp_write, hash, keylen, &filp_write->f_pos);  //writing the hash value to file
	printk (KERN_ALERT "\nBytes_write = %d", bytes_write);
	bytes_write = vfs_write(filp_write, padstring, sizeof(int), &filp_write->f_pos);  //appending pad bytes
	printk (KERN_ALERT "\nBytes written after padding = %d", bytes_write);

exit:
	return ret;
}

//During decryption
int preamble_check(struct file *filp_read, char *buf, char *hash, char *chkbuf, int keylen, int *num_bytes_padded)
{
	int i,ret,bytes_read;
	char padstring[sizeof(int)];
	ret=khash(buf, keylen, hash);
	if(ret)
	{
	    goto exit;
	}
	bytes_read = vfs_read(filp_read, chkbuf, keylen, &filp_read->f_pos);
	for(i=0;i<16;i++)
	{
	    if(hash[i]!=chkbuf[i])
	    {
		printk(KERN_ERR "\n Hashes dont match sorry!");
		ret=-1;
	    }
	}
	bytes_read = vfs_read(filp_read, padstring, sizeof(int), &filp_read->f_pos);
	memcpy(num_bytes_padded, padstring, sizeof(int)); 
exit:
	return ret;

}
int khash(char *buf, int key_len, char *hash)   //khash - Kernel level hash function
{
	struct scatterlist sg;
	struct crypto_hash *hash_tfm;
	struct hash_desc desc;
       int ret;
       
	hash_tfm = crypto_alloc_hash("md5", 0, 0);
	if(IS_ERR(hash_tfm))
		{return PTR_ERR(hash_tfm); }
	
 	desc.tfm = hash_tfm;
	sg_set_buf(&sg, buf, key_len);
	
	memset(hash, 0, key_len);
	ret = crypto_hash_digest(&desc, &sg, key_len, hash);
       
	crypto_free_hash(hash_tfm);

	return ret;
}
 int aes_encrypt(char *buf, unsigned int keylen, void *read_buf, size_t src_len)

{
	
	struct scatterlist sg;
	struct blkcipher_desc desc;
	int ret;
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm))
		{return PTR_ERR(tfm);}
       desc.tfm = tfm;
	desc.flags=0;
	
	ret = crypto_blkcipher_setkey((void *)tfm, buf, keylen);
	if(ret)
	{
		printk(KERN_ALERT "\n setkey failed\n");
		goto free_tfm;
	}
		
	printk(KERN_ALERT "\n setkey passed\n");
	sg_set_buf(&sg, read_buf, src_len);
	
	ret = crypto_blkcipher_encrypt(&desc, &sg, &sg, src_len);
	if (ret)
	{	
              goto free_tfm;
	}
free_tfm:
       crypto_free_blkcipher(tfm); 
	return ret;
}


int aes_decrypt(char *buf, unsigned int keylen, void *read_buf, size_t src_len)
{
	struct scatterlist sg;
	struct blkcipher_desc desc;
	int ret=0;
	
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm))
		{return PTR_ERR(tfm);}
       desc.tfm = tfm;
	desc.flags=0;

	ret=crypto_blkcipher_setkey((void *)tfm, buf, keylen);
	if(ret)
	{
		goto free_tfm;
	}
	sg_set_buf(&sg, read_buf, src_len);
		
	ret = crypto_blkcipher_decrypt(&desc, &sg, &sg, src_len);
	if (ret)
	{	
              goto free_tfm;
	}

free_tfm:	
	crypto_free_blkcipher(tfm); 
	return ret;
}



static int __init hello_2_init(void)
{
        mysyscall=syscrypt;
	printk(KERN_ALERT "Initializing...\n");
	return 0;
}

static void __exit hello_2_exit(void)
{
	printk(KERN_INFO "Sign off\n");
        mysyscall=NULL;
}

module_init(hello_2_init);
module_exit(hello_2_exit);

