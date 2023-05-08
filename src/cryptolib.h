#ifndef CRYPTO_LIB_H
#define CRYPTO_LIB_H

#include <string>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/rsa.h>
#include <cryptopp/dh.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

void GenerateRSAKeyPair(int keyLength, string &privateKey, string &publicKey);
string EncryptAES_CBC(const string &plainText, const SecByteBlock &key, const CryptoPP::byte *iv);
string DecryptAES_CBC(const string &cipherText, const SecByteBlock &key, const CryptoPP::byte *iv);
void DiffieHellmanKeyExchange(AutoSeededRandomPool &rng, SecByteBlock &sharedKey);
string GenerateSHA256Hash(const string &message);

#endif // CRYPTO_LIB_H
