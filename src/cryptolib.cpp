#include "cryptolib.h"

using namespace std;
using namespace CryptoPP;

void GenerateRSAKeyPair(int keyLength, string &privateKey, string &publicKey) {
    AutoSeededRandomPool rng;

    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rng, keyLength);

    RSA::PublicKey rsaPublic(rsaPrivate);

    HexEncoder privKeyEncoder(new StringSink(privateKey));
    rsaPrivate.Save(privKeyEncoder);
    privKeyEncoder.MessageEnd();

    HexEncoder pubKeyEncoder(new StringSink(publicKey));
    rsaPublic.Save(pubKeyEncoder);
    pubKeyEncoder.MessageEnd();
}

string EncryptAES_CBC(const string &plainText, const SecByteBlock &key, const byte *iv) {
    string cipherText;

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    StreamTransformationFilter stf(encryptor, new StringSink(cipherText));
    stf.Put(reinterpret_cast<const byte *>(plainText.data()), plainText.size());
    stf.MessageEnd();

    return cipherText;
}

string DecryptAES_CBC(const string &cipherText, const SecByteBlock &key, const byte *iv) {
    string decryptedText;

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    StreamTransformationFilter stf(decryptor, new StringSink(decryptedText));
    stf.Put(reinterpret_cast<const byte *>(cipherText.data()), cipherText.size());
    stf.MessageEnd();

    return decryptedText;
}

void SimulatePublicKeyExchange(const SecByteBlock &publicKeyToSend, SecByteBlock &publicKeyToReceive) {
    publicKeyToReceive.Assign(publicKeyToSend.data(), publicKeyToSend.size());
}

void DiffieHellmanKeyExchange(AutoSeededRandomPool &rng, SecByteBlock &sharedKey) {
    DH dh;
    dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, 2048);

    SecByteBlock privateKey(dh.PrivateKeyLength());
    SecByteBlock publicKey(dh.PublicKeyLength());

    dh.GenerateKeyPair(rng, privateKey, publicKey);

    // Simulate the exchange of public keys with the other party
    SecByteBlock otherPartyPrivateKey(dh.PrivateKeyLength());
    SecByteBlock otherPartyPublicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, otherPartyPrivateKey, otherPartyPublicKey);

    // Assume both parties call SimulatePublicKeyExchange
    SecByteBlock exchangedPublicKey(dh.PublicKeyLength());
    SimulatePublicKeyExchange(publicKey, exchangedPublicKey);

    sharedKey.resize(dh.AgreedValueLength());
    if (!dh.Agree(sharedKey, privateKey, exchangedPublicKey)) {
        throw runtime_error("Failed to reach a shared secret.");
    }
}

//-------------------------------------------------------------------

string GenerateSHA256Hash(const string &message) {
    SHA256 hash;
    string digest;

    StringSource(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    
    return digest;
}