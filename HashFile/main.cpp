#include <iostream>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <string>

int main(int argc, char* argv[]){
    CryptoPP::SHA256 hash;
    std::string digest;
    
    for(int i = 1; i < argc; i++){
        CryptoPP::FileSource s(argv[i], true, 
            new CryptoPP::HashFilter(hash, 
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest)
                )
            )
        );
        std::cout << "File " << i << " hash: " <<  digest << std::endl;
        digest.clear();
    }

    
    return 0;
}