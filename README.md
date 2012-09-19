Kernel-Level-File-Security
==========================

This is Native Kernel level Cryptography of files in linux. Basically an input file called infile is the file input to a user-level program called cipher.c 
which makes a system call to the kernel module which is programmed to encrypt (or decrypt) the file passed to it from the user's commandline 
via the user-level program. The options given at commandline are the password, the hash function, the encryption (or decryption) flag and the name 
of the input file. The output is stored in a file called outfile (in the case of encryption). The password is hashed twice. 
Once at the user-level and then at once again inside the kernel. MD5 hashing is used. The actual encryption algorithm used is the AES algorithm in conjunction
with the linux crypto-API. A summary of some important files and certain key methods is given below. Please refer to the kernel HOW-TO's at tldp.org on how to 
create a new system call. In this case the SYSCALL table has the entry sys_crypt (This will be clear once you define a system call).

sys_crypt.c is the loadable module:-

buf - keybuf in kernel space

syscrypt(...) is the system call

hashcheck sees if hash function khash returns success

hash is the buffer which stores the hash value

read_buf is the buffer set to PAGE_CACHE_SIZE used to read from file

output file is written into from read_buf

preamble_check is used to check the success of encryption and decryption

preamble_write writes the preamble into the file with padding

preamble_check checks for a match

khash is the function that performs hashing at kernel level

aes_encrypt is the function used to encrypt the infile

aes_decrypt decrypts the input file


crypt.c is the syscall (system call) that is built statically into the kernel


cipher.c is the userland program :-


pvalue stores the value of the password. This has to be greater than or equal to six. This is then hashed first in userland.
Then the userland hash is passed to the kernel and there it is hashed again before encryption or decryption is performed.

The -h option in the command line gives all command line options along with their functionality

cryptflag is a flag that is used to check if encryption and decryption are performed together

file[i] represents filenames passed as arguments to the command line.

DISCLAIMER:

Disclaimer:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


