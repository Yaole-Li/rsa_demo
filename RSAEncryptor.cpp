#include "RSAEncryptor.h"

// 构造函数，初始化 rsaKey 为 nullptr
RSAEncryptor::RSAEncryptor() : rsaKey(nullptr) {}

// 析构函数，释放 rsaKey 资源
RSAEncryptor::~RSAEncryptor() {
    if (rsaKey) {
        RSA_free(rsaKey); // 释放 RSA 密钥
    }
}

// 生成公钥和私钥
bool RSAEncryptor::generateKeys(int bits) {
    // 生成 RSA 密钥对
    rsaKey = RSA_generate_key(bits, RSA_F4, nullptr, nullptr);
    if (!rsaKey) {
        handleErrors(); // 处理错误
        return false;
    }

    // 提取公钥
    BIO* bio = BIO_new(BIO_s_mem()); // 创建内存 BIO
    PEM_write_bio_RSA_PUBKEY(bio, rsaKey); // 将公钥写入 BIO
    char* pubKeyData;
    long pubKeyLen = BIO_get_mem_data(bio, &pubKeyData); // 获取公钥数据
    publicKey = std::string(pubKeyData, pubKeyLen); // 将公钥数据转换为字符串
    BIO_free(bio); // 释放 BIO

    // 提取私钥
    bio = BIO_new(BIO_s_mem()); // 创建内存 BIO
    PEM_write_bio_RSAPrivateKey(bio, rsaKey, nullptr, nullptr, 0, nullptr, nullptr); // 将私钥写入 BIO
    char* privKeyData;
    long privKeyLen = BIO_get_mem_data(bio, &privKeyData); // 获取私钥数据
    privateKey = std::string(privKeyData, privKeyLen); // 将私钥数据转换为字符串
    BIO_free(bio); // 释放 BIO

    return true; // 返回成功
}

// 加密函数
std::string RSAEncryptor::encrypt(const std::string& plaintext) {
    std::string ciphertext(RSA_size(rsaKey), '\0'); // 初始化密文字符串
    int result = RSA_public_encrypt(plaintext.size(), 
                                    reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                                    reinterpret_cast<unsigned char*>(&ciphertext[0]), 
                                    rsaKey, 
                                    RSA_PKCS1_OAEP_PADDING); // 使用公钥加密
    if (result == -1) {
        handleErrors(); // 处理错误
        return "";
    }
    return ciphertext; // 返回密文
}

// 解密函数
std::string RSAEncryptor::decrypt(const std::string& ciphertext) {
    std::string plaintext(RSA_size(rsaKey), '\0'); // 初始化明文字符串
    int result = RSA_private_decrypt(ciphertext.size(), 
                                      reinterpret_cast<const unsigned char*>(ciphertext.c_str()), 
                                      reinterpret_cast<unsigned char*>(&plaintext[0]), 
                                      rsaKey, 
                                      RSA_PKCS1_OAEP_PADDING); // 使用私钥解密
    if (result == -1) {
        handleErrors(); // 处理错误
        return "";
    }
    return plaintext.substr(0, result); // 返回解密后的明文
}

// 获取公钥
std::string RSAEncryptor::getPublicKey() {
    return publicKey; // 返回公钥字符串
}

// 获取私钥
std::string RSAEncryptor::getPrivateKey() {
    return privateKey; // 返回私钥字符串
}

// 错误处理函数
void RSAEncryptor::handleErrors() {
    ERR_print_errors_fp(stderr); // 打印错误信息到标准错误输出
    abort(); // 终止程序
}
