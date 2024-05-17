#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define MAX_FILENAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define BUFFER_SIZE 4096

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encryptFile(const char *inputFile, const char *outputFile, const char *password, int algorithm);
int decryptFile(const char *inputFile, const char *outputFile, const char *password, int algorithm);
void xorEncryptDecryptFile(const char* filename, const char* newFilename, const char* password);

int main()
{
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    int choice;
    char inputFile[MAX_FILENAME_LENGTH];
    char outputFile[MAX_FILENAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];

    printf("Choose an option:\n");
    printf("1. Encrypt a file using AES-256-CBC\n");
    printf("2. Encrypt a file using Triple DES (3DES)\n");
    printf("3. Decrypt a file using AES-256-CBC\n");
    printf("4. Decrypt a file using Triple DES (3DES)\n");
    printf("5. Encrypt a file using XOR\n");
    printf("6. Decrypt a file using XOR\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);

    switch (choice) {
        case 1:
        case 2:
        case 3:
        case 4:
            printf("Enter the input file name: ");
            scanf("%s", inputFile);
            printf("Enter the output file name: ");
            scanf("%s", outputFile);
            printf("Enter the password: ");
            scanf("%s", password);

            if (choice == 1 || choice == 2) {
                if (encryptFile(inputFile, outputFile, password, choice)) {
                    printf("File encrypted successfully\n");
                } else {
                    printf("Error encrypting file\n");
                }
            } else if (choice == 3 || choice == 4) {
                if (decryptFile(inputFile, outputFile, password, choice - 2)) {
                    printf("File decrypted successfully\n");
                } else {
                    printf("Error decrypting file\n");
                }
            }
            break;

        case 5:
        case 6:
            printf("Enter the input file name: ");
            scanf("%s", inputFile);
            printf("Enter the output file name: ");
            scanf("%s", outputFile);
            printf("Enter the password: ");
            scanf("%s", password);

            if (choice == 5 || choice == 6) {
                xorEncryptDecryptFile(inputFile, outputFile, password);
                printf("File encrypted/decrypted successfully\n");
            }
            break;

        default:
            printf("Invalid choice\n");
            break;
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

int encryptFile(const char *inputFile, const char *outputFile, const char *password, int algorithm)
{
    FILE *inFile = fopen(inputFile, "rb");
    if (!inFile) {
        printf("Error opening input file");
        return 0;
    }

    FILE *outFile = fopen(outputFile, "wb");
    if (!outFile) {
        printf("Error opening output file");
        fclose(inFile);
        return 0;
    }

    const EVP_CIPHER *cipher;
    if (algorithm == 1) {
        cipher = EVP_aes_256_cbc();
    } else if (algorithm == 2) {
        cipher = EVP_des_ede3_cbc();
    } else {
        printf("Invalid algorithm choice");
        fclose(inFile);
        fclose(outFile);
        return 0;
    }

    const unsigned char *iv = (unsigned char *)"0123456789012345";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char *)password, iv)) {
        handleErrors();
    }

    unsigned char inBuf[BUFFER_SIZE], outBuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytesRead, bytesWritten;

    while (1) {
        bytesRead = fread(inBuf, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;
        if (!EVP_EncryptUpdate(ctx, outBuf, &bytesWritten, inBuf, bytesRead)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(inFile);
            fclose(outFile);
            handleErrors();
        }
        fwrite(outBuf, 1, bytesWritten, outFile);
    }

    if (!EVP_EncryptFinal_ex(ctx, outBuf, &bytesWritten)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inFile);
        fclose(outFile);
        handleErrors();
    }
    fwrite(outBuf, 1, bytesWritten, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);

    return 1;
}

int decryptFile(const char *inputFile, const char *outputFile, const char *password, int algorithm)
{
    FILE *inFile = fopen(inputFile, "rb");
    if (!inFile) {
        printf("Error opening input file");
        return 0;
    }

    FILE *outFile = fopen(outputFile, "wb");
    if (!outFile) {
        printf("Error opening output file");
        fclose(inFile);
        return 0;
    }

    const EVP_CIPHER *cipher;
    if (algorithm == 1) {
        cipher = EVP_aes_256_cbc();
    } else if (algorithm == 2) {
        cipher = EVP_des_ede3_cbc();
    } else {
        printf("Invalid algorithm choice");
        fclose(inFile);
        fclose(outFile);
        return 0;
    }

    const unsigned char *iv = (unsigned char *)"0123456789012345";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)password, iv)) {
        handleErrors();
    }

    unsigned char inBuf[BUFFER_SIZE], outBuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytesRead, bytesWritten;

    while (1) {
        bytesRead = fread(inBuf, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;
        if (!EVP_DecryptUpdate(ctx, outBuf, &bytesWritten, inBuf, bytesRead)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(inFile);
            fclose(outFile);
            handleErrors();
        }
        fwrite(outBuf, 1, bytesWritten, outFile);
    }

    if (!EVP_DecryptFinal_ex(ctx, outBuf, &bytesWritten)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(inFile);
        fclose(outFile);
        handleErrors();
    }
    fwrite(outBuf, 1, bytesWritten, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);

    return 1;
}

void xorEncryptDecryptFile(const char* filename, const char* newFilename, const char* password)
{
    FILE *inputFile, *outputFile;
    unsigned char buffer[BUFFER_SIZE];
    size_t keyLength = strlen(password);
    size_t bytesRead;
    size_t keyIndex = 0;

    inputFile = fopen(filename, "rb");
    if (!inputFile) {
        printf("Error opening input file: %s\n", filename);
        return;
    }
    outputFile = fopen(newFilename, "wb");
    if (!outputFile) {
        printf("Error creating output file: %s\n", newFilename);
        fclose(inputFile);
        return;
    }

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            buffer[i] ^= password[keyIndex];
            keyIndex = (keyIndex + 1) % keyLength;
        }
        fwrite(buffer, 1, bytesRead, outputFile);
    }

    fclose(inputFile);
    fclose(outputFile);

    printf("Operation complete. Output file: %s\n", newFilename);
}

