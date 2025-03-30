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
    typedef unsigned char Key;
    typedef Key PublicKey[crypto_box_PUBLICKEYBYTES];
    typedef Key PrivateKey[crypto_box_SECRETKEYBYTES];

    typedef std::vector<uint8_t> Data;

    struct KeyPair {
        PublicKey publicKey;
        PrivateKey privateKey;
    };

    // generate deterministic key pair from seed
    void GenerateKeyPairFromSeed(const std::string& license, KeyPair& keyPair);


    // ------------------- encryption & decryption ---------------------

    /// Encrypt data using the public key.
    /// @param pubkey The public key to use for encryption.
    /// @param dataToEncrypt The data to be encrypted.
    /// @param encryptedData The resulting encrypted data.
    void Encrypt(const PublicKey& pubkey, const Data& dataToEncrypt, Data& encryptedData);

    /// Decrypt data using the private key.
    /// @param keyPair The keypair with the public key used for encryption.
    /// @param encryptedData The encrypted data to be decrypted.
    /// @param decryptedData The vector that will contain the decrypted data.
    void Decrypt(const KeyPair& keyPair, const Data& encryptedData, Data& decryptedData);
}