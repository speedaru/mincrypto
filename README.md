# mincrypto

`mincrypto` is a C++ library that simplifies encryption and decryption using the [libsodium](https://github.com/jedisct1/libsodium) cryptographic library. It provides an easy-to-use interface for generating deterministic key pairs from a seed, as well as encrypting and decrypting data using public and private keys.

## Features

- Generate deterministic key pairs from a license string.
- Encrypt and decrypt data using public and private keys.
- Uses [libsodium](https://libsodium.gitbook.io/doc/) for cryptography, ensuring strong, secure encryption algorithms.

## Installation

To use `mincrypto`, you'll need these .lib files: libcrypto.lib  libsodium.lib  libssh2.lib  libssl.lib

### libsodium.lib
you can get libsodium by downloading the precompiled library from libsodium github
- [libsodium](https://github.com/jedisct1/libsodium/releases)

### libcrypto.lib and libssl.lib:
you can get libcrypto.lib and libssl.lib by building openssl from source or using vcpkg
- [openssl](https://github.com/openssl/openssl)
- [vcpkg](https://github.com/microsoft/vcpkg)

run bootstrap-vcpkg
then run: vcpkg install openssl
it will build openssl for you
then you can find libcrypto.lib and libssl.lib in buildtrees\openssl\x64-windows-rel

### libssh2.lib:
you can get libssh2.lib using the same methods as above
- [libssh2](https://github.com/libssh2/libssh2)
- [vcpkg](https://github.com/microsoft/vcpkg)

for vcpkg run: vcpkg install libssh2:x64-windows-static
it will build libssh2 for you
you can find libssh2.lib in packages\libssh2_x64-windows-static\lib

## Usage

### Generate a Deterministic Key Pair

```cpp
#include <mincrypto.h>

mincrypto::KeyPair keyPair;
std::string license = "some-license-string";
mincrypto::GenerateKeyPairFromSeed(license, keyPair);
```

### Encrypt Data

```cpp
#include <mincrypto.h>

mincrypto::PublicKey pubkey; // set this to the public key you want to encrypt with
mincrypto::Data dataToEncrypt = { /* your data */ };
mincrypto::Data encryptedData;

mincrypto::Encrypt(pubkey, dataToEncrypt, encryptedData);
```

### Decrypt Data

```cpp
#include <mincrypto.h>

mincrypto::KeyPair keyPair; // keypair containing the private key
mincrypto::Data encryptedData = { /* your encrypted data */ };
mincrypto::Data decryptedData;

mincrypto::Decrypt(keyPair, encryptedData, decryptedData);
```

Functions
---------

### `GenerateKeyPairFromSeed(const std::string& license, KeyPair& keyPair)`

Generates a deterministic key pair from the given license string (seed).

### `Encrypt(const PublicKey& pubkey, const Data& dataToEncrypt, Data& encryptedData)`

Encrypts data using the provided public key.

### `Decrypt(const KeyPair& keyPair, const Data& encryptedData, Data& decryptedData)`

Decrypts the encrypted data using the provided private key from the key pair.

Example
-------

Here’s a full example that shows how to generate a key pair, encrypt data, and then decrypt it.

```cpp
#include <mincrypto.h>
#include <iostream>

int main() {
    std::string license = "some-license-string";
    mincrypto::KeyPair keyPair;
    
    // generate key pair from seed
    mincrypto::GenerateKeyPairFromSeed(license, keyPair);

    // data to encrypt
    mincrypto::Data dataToEncrypt = {1, 2, 3, 4, 5};
    mincrypto::Data encryptedData;

    // encrypt data
    mincrypto::Encrypt(keyPair.publicKey, dataToEncrypt, encryptedData);

    // decrypt data
    mincrypto::Data decryptedData;
    mincrypto::Decrypt(keyPair, encryptedData, decryptedData);

    // output decrypted data
    std::cout << "decrypted data: ";
    for (const auto& byte : decryptedData) {
        std::cout << (int)byte << " ";
    }
    std::cout << std::endl;
}
```

