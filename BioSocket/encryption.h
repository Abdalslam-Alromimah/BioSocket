// include/core/encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

class Encryption {
public:
    Encryption();
    ~Encryption();
    
    std::vector<unsigned char> generateAESKey();
    std::vector<unsigned char> encryptAESKeyWithRSA(const std::vector<unsigned char>& aesKey);
    std::vector<unsigned char> encryptMessageWithAES(const std::string& message, 
                                                   const std::vector<unsigned char>& aesKey,
                                                   std::vector<unsigned char>& iv);
    std::vector<unsigned char> decryptAESKeyWithRSA(const std::vector<unsigned char>& encryptedKey);
    std::string decryptMessageWithAES(const std::vector<unsigned char>& encryptedMessage,
                                    const std::vector<unsigned char>& aesKey,
                                    const std::vector<unsigned char>& iv);

    std::vector<unsigned char> generateIV(size_t ivSize = 16);

private:
    void initializeOpenSSL();
    void cleanupOpenSSL();
};

#endif // ENCRYPTION_H
