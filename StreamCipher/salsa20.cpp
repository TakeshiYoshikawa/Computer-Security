#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/salsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"

#include <iostream>
#include <string>


class Printer{
    private:
    public:
        std::string print(CryptoPP::SecByteBlock info){
            std::string encoded;
            
            encoded.clear();
            CryptoPP::StringSource(info, info.size(), true,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(encoded)
                ) 
            );

            return encoded;
        }

        std::string print(std::string info){
            std::string encoded;
            
            encoded.clear();
            CryptoPP::StringSource(info, true,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(encoded)
                ) 
            );

            return encoded;
        }
};

class Salsa20{
    private:
        std::string cipher;
        std::string recover;
    public:
        std::string getCipher(){ return cipher; }

        std::string getRecovered(){ return recover; }
        
        void encrypt(std::string plain, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv){
            CryptoPP::Salsa20::Encryption e;    
            e.SetKeyWithIV(key, key.size(), iv, iv.size());
            
            cipher.resize(plain.size());
            e.ProcessData(
                //&cipher[0] is how to get the non-const pointer from a std::string.
                (CryptoPP::byte*) &cipher[0], (const CryptoPP::byte*)plain.data(), plain.size()
            );
        }

        void decrypt(std::string cipher, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv){
            CryptoPP::Salsa20::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), iv, iv.size());

            //Perform the decryption
            recover.resize(cipher.size());
            dec.ProcessData(
                (CryptoPP::byte*)&recover[0], (const CryptoPP::byte*)cipher.data(), cipher.size()
            );
        }
};

int main(){
    CryptoPP::AutoSeededRandomPool prng;
    
    std::string plain("Salsa20 stream cipher test");
    CryptoPP::SecByteBlock key(16);
    CryptoPP::SecByteBlock iv(8);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    Printer pt;
    std::cout << "key: " << pt.print(key) << std::endl;
    std::cout << "iv: " << pt.print(iv) << std::endl;
    
    Salsa20 salsa;
    salsa.encrypt(plain, key, iv);

    std::cout << "Plain: " << plain << std::endl;

    std::cout << "Cipher: " << pt.print(salsa.getCipher()) << std::endl;

    salsa.decrypt(salsa.getCipher(), key, iv);
    std::cout << "Recovered: " << salsa.getRecovered() << std::endl;
    return 0;
}