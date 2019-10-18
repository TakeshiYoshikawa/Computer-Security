#include <iostream>
#include <cryptopp/des.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h> //PKCS #5 - PBKDF
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

class PBKDF_DES{
    private:
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock key;
        CryptoPP::SecByteBlock derived_key;
        CryptoPP::byte iv[CryptoPP::DES_EDE3::BLOCKSIZE]; 
        CryptoPP::byte salt[CryptoPP::DES_EDE3::BLOCKSIZE];
        CryptoPP::PKCS5_PBKDF2_HMAC <CryptoPP::SHA256> pbkdf;
        std::string cipher;
        std::string cipher_iv;
        std::string recovered;
        
    public:
        PBKDF_DES(): key(0x00, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH), 
                     derived_key(0x00, CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH)
        {   
            prng.GenerateBlock(key, key.size());
            prng.GenerateBlock(iv, sizeof(iv));
            prng.GenerateBlock(salt, sizeof(salt));
            pbkdf.DeriveKey( derived_key, derived_key.size(), 0,
                             key, key.size(), salt, sizeof(salt), 10000);
        }

        CryptoPP::SecByteBlock& getKey(){ return key; }

        CryptoPP::SecByteBlock& getDerivedKey(){ return derived_key; }
        
        CryptoPP::byte* getIv(){ return iv; }

        CryptoPP::byte* getSalt(){ return salt; }
        
        std::string getCipherIV(){ return cipher_iv; }
        
        std::string getCipher(){ return cipher; }

        std::string getRecovered(){ return recovered; }


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

        std::string print(CryptoPP::byte* info, int length){
            std::string encoded2;

            encoded2.clear();
            CryptoPP::StringSource(info, length, true,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(encoded2)
                ) 
            ); 
            return encoded2;
        }

        std::string print(std::string info){
            std::string encoded3;

            encoded3.clear();
            CryptoPP::StringSource(info, true,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(encoded3)
                ) 
            ); 
            return encoded3;
        }

        void encrypt(std::string plain_text){
            try{
                CryptoPP::OFB_Mode <CryptoPP::DES_EDE3>::Encryption e;
                e.SetKeyWithIV(derived_key, derived_key.size(), iv);
                
                CryptoPP::StringSource(plain_text, true,
                    new CryptoPP::StreamTransformationFilter(e,
                        new CryptoPP::StringSink(cipher)
                    )
                );
            }
            catch(CryptoPP::Exception& e){
                std::cerr << e.what() << std::endl;
            }
        }

        void encrypt(CryptoPP::byte* _iv){
            try{
                CryptoPP::ECB_Mode <CryptoPP::DES_EDE3>::Encryption e;
                e.SetKey(derived_key, derived_key.size());
             
                CryptoPP::StringSource(print(_iv,CryptoPP::DES_EDE3::BLOCKSIZE), true,
                    new CryptoPP::StreamTransformationFilter(e,
                        new CryptoPP::StringSink(cipher_iv)
                    )
                );
            }
            catch(CryptoPP::Exception& e){
                std::cerr << e.what() << std::endl;
            }
        }
    
        void decrypt(){
            try{
                CryptoPP::OFB_Mode<CryptoPP::DES_EDE3>::Decryption d;
                d.SetKeyWithIV(derived_key, derived_key.size(), iv);

                CryptoPP::StringSource ss1( cipher, true, 
                    new CryptoPP::StreamTransformationFilter(d,
                        new CryptoPP::StringSink( recovered )
                    )      
                ); 
            } 
            catch(const CryptoPP::Exception& e1){
                std::cerr << e1.what() << std::endl;
                exit(1);
            }
        }

        void decrypt(std::string _cipher_iv){
            std::string recovered2;
            try{
                CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption d;
                d.SetKey(derived_key, derived_key.size());

                CryptoPP::StringSource ss1(_cipher_iv, true, 
                    new CryptoPP::StreamTransformationFilter(d,
                        new CryptoPP::StringSink( recovered2 )
                    )      
                ); 
                std::cout << "Recovered IV: " << recovered2 << std::endl;
            } 
            catch(const CryptoPP::Exception& e1){
                std::cerr << e1.what() << std::endl;
                exit(1);
            }
        }
        
};

int main(){
    PBKDF_DES process;
    
    std::string plain = "CryptoPP OFB Mode Test";

    process.encrypt(process.getIv());
    std::cout << "Cipher IV: " << process.print(process.getCipherIV()) << std::endl;
    process.decrypt(process.getCipherIV());
    
    std::cout << std::endl;

    process.encrypt(plain);
    process.decrypt();    

    std::cout << "plain text: " << plain << std::endl;
    std::cout << "Cipher Text: " << process.print(process.getCipher()) << std::endl;
    std::cout << "Recovered Text: " << process.getRecovered() << std::endl;
    std::cout << "Key: " << process.print(process.getKey()) << std::endl;
    std::cout << "Derived Key: " << process.print(process.getDerivedKey()) << std::endl;
    std::cout << "IV: " << process.print(process.getIv(), CryptoPP::DES_EDE3::BLOCKSIZE) << std::endl;
    return 0;
}