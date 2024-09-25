cmake_minimum_required(VERSION 3.10)

# 项目名称
project(RSAEncryptor)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin)

# 指定 OpenSSL 的绝对路径
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)

# 查找 OpenSSL 包
find_package(OpenSSL REQUIRED)

# 包含头文件
include_directories(${OPENSSL_INCLUDE_DIR})

# 添加源文件
set(SOURCES
    RSAEncryptor.cpp
    main.cpp
)

# 创建可执行文件
add_executable(RSAEncryptor ${SOURCES})

# 链接 OpenSSL 库
target_link_libraries(RSAEncryptor OpenSSL::SSL OpenSSL::Crypto)
