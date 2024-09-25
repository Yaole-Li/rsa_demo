#ifndef RSAENCRYPTOR_H
#define RSAENCRYPTOR_H

#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

class RSAEncryptor {
public:
    RSAEncryptor();
    ~RSAEncryptor();

    bool generateKeys(int bits);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

    std::string getPublicKey();
    std::string getPrivateKey();

private:
    RSA* rsaKey;
    std::string privateKey;
    std::string publicKey;

    void handleErrors();
};

#endif // RSAENCRYPTOR_H
