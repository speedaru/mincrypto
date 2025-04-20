#pragma once
#define SODIUM_STATIC
#include <sodium.h>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libsodium.lib")
#pragma comment(lib, "libssh2.lib")
#pragma comment(lib, "libssl.lib")

namespace mincrypto {
    typedef uint8_t PublicKey[crypto_box_PUBLICKEYBYTES];
    typedef uint8_t PrivateKey[crypto_box_SECRETKEYBYTES];

    typedef std::vector<uint8_t> Data;

    struct KeyPair {
        PublicKey publicKey;
        PrivateKey privateKey;
        void clear();
    };

    // generate deterministic key pair from seed
    void GenerateKeyPairFromSeed(const std::string& license, KeyPair& keyPair);


    // ------------------- encryption & decryption ---------------------
    // 
    // encrypt data using the public key
    void Encrypt(const PublicKey& pubkey, const Data& dataToEncrypt, Data& encryptedData);

    // decrypt data using the private key
    void Decrypt(const KeyPair& keyPair, const Data& encryptedData, Data& decryptedData);
}