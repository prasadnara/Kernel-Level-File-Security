#include<asm/unistd.h>
#include<linux/linkage.h>
#include<linux/kernel.h>
#include<linux/errno.h>
#include<linux/module.h>

int (*mysyscall)(char *infile, char *outfile, void *keybuf, unsigned int keylen, unsigned int flags) = NULL;

asmlinkage long sys_crypt(char *infile, char *outfile, void *keybuf, unsigned int keylen, unsigned int flags)
{
   if(mysyscall)
      return mysyscall(infile, outfile, keybuf, keylen, flags);
   else
      return -ENOSYS;
}

EXPORT_SYMBOL(mysyscall);

