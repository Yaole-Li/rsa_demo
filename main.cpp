#include <iostream>
#include "RSAEncryptor.h"

int main() {
    RSAEncryptor rsa;

    // 生成密钥
    if (!rsa.generateKeys(2048)) {
        std::cerr << "密钥生成失败！" << std::endl;
        return 1;
    }

    std::string plaintext = "https://www.baidu.com";
    std::cout << "原始数据: " << plaintext << std::endl;

    // 加密
    std::string ciphertext = rsa.encrypt(plaintext);
    std::cout << "加密后的数据: " << ciphertext << std::endl;

    // 解密
    std::string decryptedText = rsa.decrypt(ciphertext);
    std::cout << "解密后的数据: " << decryptedText << std::endl;

    // 输出公钥和私钥
    std::cout << "公钥: " << rsa.getPublicKey() << std::endl;
    std::cout << "私钥: " << rsa.getPrivateKey() << std::endl;

    return 0;
}

//g++ -o rsa_test main.cpp RSAEncryptor.cpp -lssl -lcrypto