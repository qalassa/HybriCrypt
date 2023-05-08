#include <iostream>
#include "cryptolib.h"

using namespace std;
using namespace CryptoPP;

void print_menu() {
    cout << "Choose an option:" << endl;
    cout << "1. Generate RSA key pair" << endl;
    cout << "2. Diffie-Hellman Key Exchange" << endl;
    cout << "3. Encrypt message using AES-CBC" << endl;
    cout << "4. Decrypt message using AES-CBC" << endl;
    cout << "5. Generate SHA-256 hash" << endl;
    cout << "6. Exit" << endl;
}

int main() {
    int choice;
    AutoSeededRandomPool rng;
    SecByteBlock sharedKey;

    do {
        print_menu();
        cin >> choice;
        cin.ignore();

        switch (choice) {
            case 1: {
                string privateKey, publicKey;
                GenerateRSAKeyPair(2048, privateKey, publicKey);
                cout << "Private key: " << privateKey << endl;
                cout << "Public key: " << publicKey << endl;
                break;
            }
            case 2: {
                DiffieHellmanKeyExchange(rng, sharedKey);
                cout << "Shared key: ";
                for (size_t i = 0; i < sharedKey.size(); i++) {
                    cout << hex << (int)sharedKey[i];
                }
                cout << endl;
                break;
            }
            case 3: {
                if (sharedKey.empty()) {
                    cout << "Please perform Diffie-Hellman key exchange first." << endl;
                    break;
                }
                cout << "Enter the message to encrypt: ";
                string plainText;
                getline(cin, plainText);
                byte iv[AES::BLOCKSIZE];
                rng.GenerateBlock(iv, sizeof(iv));
                string cipherText = EncryptAES_CBC(plainText, sharedKey, iv);
                cout << "Encrypted message: " << cipherText << endl;
                break;
            }
            case 4: {
                if (sharedKey.empty()) {
                    cout << "Please perform Diffie-Hellman key exchange first." << endl;
                    break;
                }
                cout << "Enter the message to decrypt: ";
                string cipherText;
                getline(cin, cipherText);
                byte iv[AES::BLOCKSIZE];
                rng.GenerateBlock(iv, sizeof(iv));
                string decryptedText = DecryptAES_CBC(cipherText, sharedKey, iv);
                cout << "Decrypted message: " << decryptedText << endl;
                break;
            }
            case 5: {
                cout << "Enter the message to hash: ";
                string message;
                getline(cin, message);
                string hash = GenerateSHA256Hash(message);
                cout << "SHA-256 hash: " << hash << endl;
                break;
            }
            case 6:
                cout << "Exiting..." << endl;
                break;
            default:
                cout << "Invalid option. Please try again." << endl;
        }
    } while (choice != 6);

    return 0;
}