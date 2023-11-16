#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

void calculate_sha256(const char *input_string, unsigned char *output_hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input_string, strlen(input_string));
    SHA256_Final(output_hash, &sha256);
}

int main() {
    const char *input_string = "Hello, World!";
    unsigned char hash[SHA256_DIGEST_LENGTH];

    calculate_sha256(input_string, hash);

    printf("SHA-256 Hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
