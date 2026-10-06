#ifndef __AES_CSDK_H__
#define __AES_CSDK_H__

#define AES_BLOCK_SIZE 16

#define AES_MAXNR 14


struct aes_key_st {
#  ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
#  else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
#  endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

void AES_CSK_encrypt (const void *inp,void *out,const AES_KEY *key);
void AES_CSDK_decrypt (const void *inp,void *out,const AES_KEY *key);
int AES_CSDK_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_CSDK_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

#endif
