#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFER_SIZE 256
#define KEY_SIZE 32 // for EVP_aes_256_cbc()

void create_key_iv(unsigned char salt[PKCS5_SALT_LEN], unsigned char key[EVP_MAX_KEY_LENGTH], unsigned char iv[EVP_MAX_IV_LENGTH])
{
    const char *str = "key45678901234567890123456789012";
    const int str_len = strlen(str);
    const int iter = 10000;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int iklen = EVP_CIPHER_key_length(cipher);
    const int ivlen = EVP_CIPHER_iv_length(cipher);
    const EVP_MD *dgst = EVP_sha256();
    const int islen = PKCS5_SALT_LEN;
    unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];

    PKCS5_PBKDF2_HMAC(str, str_len, salt, islen, iter, dgst, iklen+ivlen, tmpkeyiv);

    memcpy(key, tmpkeyiv, iklen);
    memcpy(iv, tmpkeyiv+iklen, ivlen);
}

/*!
    https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/
int main(int argc, char *argv[])
{
    int ret;
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // https://linux.die.net/man/3/evp_decryptupdate
    unsigned char plaintext[BUFFER_SIZE+KEY_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    int plaintext_len;
    unsigned char salt[PKCS5_SALT_LEN] = "";
    unsigned char key[EVP_MAX_KEY_LENGTH] = "";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "";
    FILE * fpIn = NULL;
    FILE * fpOut = NULL;
    unsigned char * infile = NULL;
    unsigned char * outfile = NULL;
    static const char magic[] = "Salted__";
    unsigned char readmagic[sizeof(magic) - 1] = "";
    size_t n;

    infile = argv[1];
    outfile = argv[2];
    outfile = argv[2];

    fpIn = fopen(infile, "rb");
    if (fpIn == NULL) {
        printf("ERROR: fopen(%s)\n", infile);
        return 1;
    }

    fpOut = fopen(outfile, "wb");
    if (fpOut == NULL) {
        fclose(fpIn);
        printf("ERROR: fopen(%s)\n", outfile);
        return 1;
    }

    n = fread(readmagic, 1, sizeof(readmagic), fpIn);
    if (n != sizeof(readmagic)) {
        fclose(fpOut);
        fclose(fpIn);
        printf("ERROR: fread(magic)\n");
        return 1;
    }
    if (memcmp(readmagic, magic, sizeof(readmagic)) != 0){
        fclose(fpOut);
        fclose(fpIn);
        printf("ERROR: readmagic\n");
        return 1;
    }
    n = fread(salt, 1, sizeof(salt), fpIn);
    if (n != sizeof(salt)) {
        fclose(fpOut);
        fclose(fpIn);
        printf("ERROR: fread(salt)\n");
        return 1;
    }
    create_key_iv(salt, key, iv);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fclose(fpOut);
        fclose(fpIn);
        printf("ERROR: EVP_CIPHER_CTX_new()\n");
        return 1;
    }

    ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printf("ERROR: EVP_DecryptInit_ex()\n");
        return 1;
    }

    printf("EVP_CIPHER_CTX_key_length() : keysize = %d\n", EVP_CIPHER_CTX_key_length(ctx));

    while(1){
        n = fread(ciphertext, 1, BUFFER_SIZE, fpIn);
        if (n > 0 ){
            ciphertext_len = n;

            /*
                Quoted from https://linux.die.net/man/3/evp_decryptupdate

                EVP_DecryptUpdate() should have sufficient room for (inl + cipher_block_size) bytes
                unless the cipher block size is 1 in which case inl bytes is sufficient.
            */

            // Set Output buffer size
            len = sizeof(plaintext);

            ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
            if (ret != 1) {
                fclose(fpOut);
                fclose(fpIn);
                EVP_CIPHER_CTX_free(ctx);
                printf("ERROR: EVP_DecryptUpdate()\n");
                return 1;
            }
            fwrite(plaintext, 1, len, fpOut);
            printf("wrote: %u\n", len);
        }
        else {
            // Set Output buffer size
            len = sizeof(plaintext);

            ret = EVP_DecryptFinal_ex(ctx, plaintext, &len);
            if (ret != 1) {
                fclose(fpOut);
                fclose(fpIn);
                EVP_CIPHER_CTX_free(ctx);
                printf("ERROR: EVP_DecryptFinal_ex()\n");
                return 1;
            }
            fwrite(plaintext, 1, len, fpOut);
            printf("wrote: %u\n", len);
            break;
        }
    }
    fclose(fpOut);
    fclose(fpIn);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
