#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/salsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <string>

int main(){

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::HexEncoder encoder(
        new CryptoPP::FileSink(std::cout)
    );

    std::string plain("O cara tentou resolver P = NP será que tá certo?"), cipher, recover;

    CryptoPP::SecByteBlock key(16), iv(8);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::cout << "Key: ";
    encoder.Put((const CryptoPP::byte*)key.data(), key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "IV: ";
    encoder.Put((const CryptoPP::byte*)iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Encryption object
    CryptoPP::Salsa20::Encryption enc;    
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    /*  Perform the encryption
        Using Salsa20::Encryption and Salsa20::Decryption. 
        &cipher[0] is how to get the non-const pointer from a std::string. */
    
    cipher.resize(plain.size());
    enc.ProcessData(
        (CryptoPP::byte*)&cipher[0], (const CryptoPP::byte*)plain.data(), plain.size()
    );

    std::cout << "Plain: " << plain << std::endl;

    std::cout << "Cipher: ";

    encoder.Put((const CryptoPP::byte*)cipher.data(), cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    CryptoPP::Salsa20::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the decryption
    recover.resize(cipher.size());
    dec.ProcessData(
        (CryptoPP::byte*)&recover[0], (const CryptoPP::byte*)cipher.data(), cipher.size()
    );

    std::cout << "Recovered: " << recover << std::endl;

    return 0;
}