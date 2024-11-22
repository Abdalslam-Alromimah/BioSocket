#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>
#include <cstdio>

Encryption::Encryption() {
    initializeOpenSSL();
}

Encryption::~Encryption() {
    cleanupOpenSSL();
}

void Encryption::initializeOpenSSL() {
    // Initialize OpenSSL
    EVP_add_cipher(EVP_aes_256_cbc());
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void Encryption::cleanupOpenSSL() {
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}


std::vector<unsigned char> Encryption::generateIV(size_t ivSize) {
    std::vector<unsigned char> iv(ivSize);
    std::random_device rd;
    std::generate(iv.begin(), iv.end(), [&]() { return rd() % 256; });
    return iv;
}


std::vector<unsigned char> Encryption::generateAESKey() {
    std::vector<unsigned char> key(32); // 256-bit key
    if (RAND_bytes(key.data(), key.size()) != 1) {
        throw std::runtime_error("Failed to generate random AES key");
    }
    return key;
}

std::vector<unsigned char> Encryption::encryptAESKeyWithRSA(const std::vector<unsigned char>& aesKey) {
    // Load public key from file (adjust the path accordingly)
    const char* pubKeyPath = "E:\\BioSocket\\BioSocket\\rsa_public_key.pem";  // Adjust path as needed

    BIO* pubKeyBio = BIO_new_file(pubKeyPath, "r");
    if (!pubKeyBio) {
        throw std::runtime_error("Could not open public key file");
    }

    // Read the public key from the BIO (this returns an EVP_PKEY object)
    EVP_PKEY* evpPubKey = PEM_read_bio_PUBKEY(pubKeyBio, nullptr, nullptr, nullptr);
    if (!evpPubKey) {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);  // Print OpenSSL errors to stderr
        BIO_free(pubKeyBio);  // Free BIO
        throw std::runtime_error("Failed to read public key");
    }

    // Convert the EVP_PKEY to an RSA object
    RSA* rsa = EVP_PKEY_get1_RSA(evpPubKey);
    EVP_PKEY_free(evpPubKey);  // Free EVP_PKEY after extracting RSA key
    BIO_free(pubKeyBio);  // Free the BIO

    if (!rsa) {
        throw std::runtime_error("Failed to convert EVP_PKEY to RSA");
    }

    // Allocate buffer for encrypted key
    std::vector<unsigned char> encryptedKey(RSA_size(rsa));

    // Encrypt the AES key with RSA
    int encryptedLength = RSA_public_encrypt(
        aesKey.size(),
        aesKey.data(),
        encryptedKey.data(),
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    RSA_free(rsa);  // Free RSA object

    if (encryptedLength == -1) {
        throw std::runtime_error("RSA encryption failed");
    }

    encryptedKey.resize(encryptedLength);
    return encryptedKey;
}

std::vector<unsigned char> Encryption::encryptMessageWithAES(
    const std::string& message,
    const std::vector<unsigned char>& aesKey,
    std::vector<unsigned char>& iv
) {
    // Generate random IV
    iv.resize(AES_BLOCK_SIZE);
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> encryptedMessage(message.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0;
    int outLen2 = 0;

    // Encrypt message
    if (EVP_EncryptUpdate(ctx,
                         encryptedMessage.data(),
                         &outLen1,
                         reinterpret_cast<const unsigned char*>(message.data()),
                         message.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt message");
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, encryptedMessage.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    EVP_CIPHER_CTX_free(ctx);
    encryptedMessage.resize(outLen1 + outLen2);
    return encryptedMessage;
}
/*
std::vector<unsigned char> Encryption::decryptAESKeyWithRSA(const std::vector<unsigned char>& encryptedKey) {
    // Load private key from file (you should modify the path accordingly)
    const char* prvKeyPath = "E:\\BioSocket\\BioSocket\\rsa_key.pem";  // Adjust path as needed
    FILE* privKeyFile = fopen(prvKeyPath, "rb");

    if (!privKeyFile) {
        throw std::runtime_error("Could not open private key file");
    }

    RSA* rsa = PEM_read_RSAPrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);

    if (!rsa) {
        throw std::runtime_error("Failed to load RSA private key");
    }

    // Allocate buffer for decrypted key
    std::vector<unsigned char> decryptedKey(RSA_size(rsa));

    // Decrypt AES key with RSA
    int decryptedLength = RSA_private_decrypt(
        encryptedKey.size(),
        encryptedKey.data(),
        decryptedKey.data(),
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    RSA_free(rsa);

    if (decryptedLength == -1) {
        throw std::runtime_error("RSA decryption failed");
    }

    decryptedKey.resize(decryptedLength);
    return decryptedKey;
}
*/
std::vector<unsigned char> Encryption::decryptAESKeyWithRSA(const std::vector<unsigned char>& encryptedKey) {
    // Load private key from file (adjust the path accordingly)
    const char* prvKeyPath = "E:\\BioSocket\\BioSocket\\rsa_key.pem";  // Adjust path as needed

    BIO* privKeyBio = BIO_new_file(prvKeyPath, "r");
    if (!privKeyBio) {
        throw std::runtime_error("Could not open private key file");
    }

    // Read the private key from the BIO (this returns an EVP_PKEY object)
    EVP_PKEY* evpPrivKey = PEM_read_bio_PrivateKey(privKeyBio, nullptr, nullptr, nullptr);
    if (!evpPrivKey) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);  // Print OpenSSL errors to stderr
        BIO_free(privKeyBio);  // Free BIO
        throw std::runtime_error("Failed to read private key");
    }

    // Convert the EVP_PKEY to an RSA object
    RSA* rsa = EVP_PKEY_get1_RSA(evpPrivKey);
    EVP_PKEY_free(evpPrivKey);  // Free EVP_PKEY after extracting RSA key
    BIO_free(privKeyBio);  // Free the BIO

    if (!rsa) {
        throw std::runtime_error("Failed to convert EVP_PKEY to RSA");
    }

    // Allocate buffer for decrypted key
    std::vector<unsigned char> decryptedKey(RSA_size(rsa));

    // Decrypt AES key with RSA
    int decryptedLength = RSA_private_decrypt(
        encryptedKey.size(),
        encryptedKey.data(),
        decryptedKey.data(),
        rsa,
        RSA_PKCS1_OAEP_PADDING
    );

    RSA_free(rsa);  // Free RSA object

    if (decryptedLength == -1) {
        throw std::runtime_error("RSA decryption failed");
    }

    decryptedKey.resize(decryptedLength);
    return decryptedKey;
}


std::string Encryption::decryptMessageWithAES(
    const std::vector<unsigned char>& encryptedMessage,
    const std::vector<unsigned char>& aesKey,
    const std::vector<unsigned char>& iv
) {
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> decryptedMessage(encryptedMessage.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0;
    int outLen2 = 0;

    // Decrypt message
    if (EVP_DecryptUpdate(ctx,
                         decryptedMessage.data(),
                         &outLen1,
                         encryptedMessage.data(),
                         encryptedMessage.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt message");
    }
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, decryptedMessage.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(decryptedMessage.data()), outLen1 + outLen2);
}
