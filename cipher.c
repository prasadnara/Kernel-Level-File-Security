#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "callme.h"
#include <string.h>
#include <errno.h>
#include <openssl/md5.h>
     
     int syscrypt(char *infile, char *outfile, void *keybuf, unsigned int keylen, unsigned int flags)
     {
	return syscall(__NR_crypt, infile, outfile, keybuf, keylen, flags);
     }
      
     int main (int argc, char **argv)
     {
      	int m;
       int i=0;
	char *infile = (char *)malloc(16*sizeof(char));
	char *outfile = (char *)malloc(16*sizeof(char));
        char *cvalue = NULL;
        unsigned char *pvalue = NULL;
        unsigned char *mdp=NULL;
        int index;
        int c;
        unsigned int len=0;
        int cryptflag=0;	//check flag.. encr decrypt not at same time
        void *keybuf = NULL;
	unsigned int keylen;
	unsigned int flags=1;
	char *file[2];
	memset(infile, 0, 16);
	memset(outfile, 0, 16);
        opterr = 0;
      
        while ((c = getopt (argc, argv, "edc:p:h")) != -1)
        switch (c)
           {
           case 'e':
             if(cryptflag==0)
		{cryptflag=1; flags=0;}
	     else
             {
		printf("\n Encrypt and Decrypt not allowed at the same time\n");
		exit(0);
	     }  
             printf("\n Encryption selected");
	      break;

           case 'd':
             if(cryptflag==0)
		cryptflag=1;
	     else
	     {
		printf("\n Encrypt and Decrypt not allowed at the same time \n");
		exit(0);
	     }
	     printf("\n Decryption selected");
            break;

	    case 'c':
             printf("\n Cipher Selection option");
             cvalue = optarg;
             break;
          
	     case 'h':
             printf("\n Help menu");
	      printf("\n -e means to encrypt");
	      printf("\n -d means to encrypt");
	      printf("\n -p means password. It expects an arg - <password>");
	      printf("\n -c is the cipher selection option <argument required>");
	      printf("\n -h means the help menu");
	      printf("\n infile is the input file, outfile is the output file");
             break;

           case 'p':
             pvalue=(unsigned char *)optarg;
             len = strlen((char *)pvalue);
	     if(len<6)
             {
		printf("\n Password not long enough\n"); exit(0);
	      }
             break;

           case '?':
             if (optopt == 'c')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if(optopt == 'p')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
             return 1;
            default:
             abort ();
           }
     
       printf ("\npvalue = %s, cvalue = %s\n",
               pvalue, cvalue);
       
	
	for (index = optind; index < argc; index++)
       {
		file[i++]=argv[index];   
	}
	if(file[i]==file[i-1])
	{
		printf("\n Cannot process same input and output filenames ");
		exit(0);
	}

	keybuf=MD5(pvalue, len, mdp);
       keylen=strlen((char *)keybuf);
     
	m=syscrypt(file[0], file[1], keybuf, keylen, flags);
        if(m==-1)
	{
  	  perror("The following error occured");
          printf("\n %d", errno);
	}
     
	return 0;
     }


