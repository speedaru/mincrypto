#include <mincrypto.h>


void mincrypto::GenerateKeyPairFromSeed(const std::string& license, KeyPair& keyPair) {
    Key seed[crypto_box_SEEDBYTES];

    // Hash the license string into a seed
    crypto_generichash(seed, sizeof(seed),
        reinterpret_cast<const unsigned char*>(license.data()), license.size(),
        nullptr, 0);

    // Generate the deterministic keypair
    crypto_box_seed_keypair(keyPair.publicKey, keyPair.privateKey, seed);

    // Securely zero out the seed to prevent memory leaks
    sodium_memzero(seed, sizeof(seed));
}


void mincrypto::Encrypt(const PublicKey& pubkey, const Data& dataToEncrypt, Data& encryptedData) {
    encryptedData = Data(dataToEncrypt.size() + crypto_box_SEALBYTES);

    if (crypto_box_seal(encryptedData.data(), dataToEncrypt.data(), dataToEncrypt.size(), pubkey) != 0) {
        throw std::runtime_error("Encryption failed");
    }
}

void mincrypto::Decrypt(const KeyPair& keyPair, const Data& encryptedData, Data& decryptedData) {
    decryptedData = Data(encryptedData.size() - crypto_box_SEALBYTES);

    if (crypto_box_seal_open(decryptedData.data(), encryptedData.data(), encryptedData.size(),
        keyPair.publicKey, keyPair.privateKey) != 0) {
        throw std::runtime_error("Decryption failed");
    }
}