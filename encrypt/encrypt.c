#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFER_SIZE 256
#define KEY_SIZE 32 // for EVP_aes_256_cbc()

/*!
    https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/
int main(int argc, char *argv[])
{
    int ret;
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char plaintext[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE+KEY_SIZE];
    int plaintext_len;
    unsigned char *key;
    unsigned char *iv;
    FILE * fpIn = NULL;
    FILE * fpOut = NULL;
    unsigned char * infile = NULL;
    unsigned char * outfile = NULL;

    infile = argv[1];
    outfile = argv[2];
    key = "iv45678901234567890123456789012";
    iv  = "iv45678901234567890123456789012";
    outfile = argv[2];

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("ERROR: EVP_CIPHER_CTX_new()\n");
        return 1;
    }

    ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("ERROR: EVP_EncryptInit_ex(%s)\n", infile);
        return 1;
    }

    fpIn = fopen(infile, "rb");
    if (fpIn == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        printf("ERROR: fopen(%s)\n", infile);
        return 1;
    }

    fpOut = fopen(outfile, "wb");
    if (fpOut == NULL) {
        fclose(fpIn);
        EVP_CIPHER_CTX_free(ctx);
        printf("ERROR: fopen(%s)\n", outfile);
        return 1;
    }

    while(1){
        size_t n = fread(plaintext, 1, BUFFER_SIZE, fpIn);
        if (n > 0 ){
            plaintext_len = n;

            /*
                Quoted from https://linux.die.net/man/3/evp_encryptupdate

                EVP_EncryptUpdate() encrypts inl bytes from the buffer in and writes the encrypted version to out.
                This function can be called multiple times to encrypt successive blocks of data.
                The amount of data written depends on the block alignment of the encrypted data:
                as a result the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)
                so outl should contain sufficient room. The actual number of bytes written is placed in outl.
            */

            // Set Output buffer size
            len = sizeof(ciphertext);

            ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
            if (ret != 1) {
                fclose(fpOut);
                fclose(fpIn);
                EVP_CIPHER_CTX_free(ctx);
                printf("ERROR: EVP_EncryptUpdate\n");
                return 1;
            }
            fwrite(ciphertext, 1, len, fpOut);
            printf("wrote: %u\n", len);
        }
        else {
            // Set Output buffer size
            len = sizeof(ciphertext);

            ret = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
            if (ret != 1) {
                fclose(fpOut);
                fclose(fpIn);
                EVP_CIPHER_CTX_free(ctx);
                printf("ERROR: EVP_EncryptFinal_ex\n");
                return 1;
            }
            fwrite(ciphertext, 1, len, fpOut);
            printf("wrote: %u\n", len);
            break;
        }
    }
    fclose(fpOut);
    fclose(fpIn);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
