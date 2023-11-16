#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define RSA_KEY_BITS 2048

void generate_key_pair(RSA **public_key, RSA **private_key) {
    BIGNUM *e = BN_new();
    RSA *keypair = RSA_new();

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate key pair
    RSA_generate_key_ex(keypair, RSA_KEY_BITS, e, NULL);

    *public_key = RSAPublicKey_dup(keypair);
    *private_key = RSAPrivateKey_dup(keypair);

    BN_free(e);
    RSA_free(keypair);
}

void rsa_encrypt(const char *plaintext, RSA *public_key, char **ciphertext) {
    int rsa_len = RSA_size(public_key);
    *ciphertext = (char *)malloc(rsa_len);

    int result = RSA_public_encrypt(strlen(plaintext) + 1, (const unsigned char *)plaintext,
                                    (unsigned char *)*ciphertext, public_key, RSA_PKCS1_PADDING);

    if (result == -1) {
        fprintf(stderr, "Encryption failed\n");
        exit(EXIT_FAILURE);
    }
}

void rsa_decrypt(const char *ciphertext, RSA *private_key, char **decrypted_text) {
    int rsa_len = RSA_size(private_key);
    *decrypted_text = (char *)malloc(rsa_len);

    int result = RSA_private_decrypt(rsa_len, (const unsigned char *)ciphertext,
                                     (unsigned char *)*decrypted_text, private_key, RSA_PKCS1_PADDING);

    if (result == -1) {
        fprintf(stderr, "Decryption failed\n");
        exit(EXIT_FAILURE);
    }
}

int main() {
    RSA *public_key, *private_key;
    char *plaintext = "Hello, RSA!";
    char *ciphertext, *decrypted_text;

    generate_key_pair(&public_key, &private_key);

    rsa_encrypt(plaintext, public_key, &ciphertext);
    printf("Encrypted: %s\n", ciphertext);

    rsa_decrypt(ciphertext, private_key, &decrypted_text);
    printf("Decrypted: %s\n", decrypted_text);

    RSA_free(public_key);
    RSA_free(private_key);
    free(ciphertext);
    free(decrypted_text);

    return 0;
}
