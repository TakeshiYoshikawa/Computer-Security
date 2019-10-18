#include <iostream>
#include <random>
#include <sstream>
#include <bitset>

std::string StringToBin(std::string words) {
    std::string binaryString = "";
    for (char& char_ : words) {
        binaryString += std::bitset<8>(char_).to_string();
    }
    return binaryString;
}

std::string BinToString(std::string data){
    std::stringstream sstream(data);
    std::string output;
    while(sstream.good())
    {
        std::bitset<8> bits;
        sstream >> bits;
        char c = char(bits.to_ulong());
        output += c;
    }
    return output;
}

class RNG{
    private:
    public:
        void generateSeed(){
            //Ressalvas sobre o uso desse gerador, faltou consultar com maior profundidade.
            std::random_device rd;
            unsigned seed = rd();
            std::default_random_engine dre(seed);
            std::srand(dre());
        }
};

class OneTimePad{
    private:
        std::bit_xor<void> bx;
        std::string key;
        std::string cipher;
        std::string original;
        int length;

    public:
        OneTimePad(int input_length){
            RNG rng;
            rng.generateSeed();
            length = input_length;
        }
        
        char generateChar(){
            static const char alphanum[] = 
            "0123456789!@#$%^&*()/_-+|'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

            int stringLength = sizeof(alphanum) - 1;
            
            return alphanum[rand() % stringLength];
        }

        std::string generateKey(){
            for(int i = 0; i < length; i++){
                key += generateChar();
            }            
            return StringToBin(key);
        }

        std::string encrypt(std::string plain){
            for(int i = 0; i < length; i++){
                cipher += plain[i] ^ key[i];
            }

            return StringToBin(cipher);
        }

        std::string decrypt(){
            for(int i = 0; i < length; i++){
                original += cipher[i] ^ key[i];
            }            
            return StringToBin(original);
        }

        std::string getOriginal(){
            return original;
        }
};


int main(){
    std::string plain = "One Time Pad";
    std::cout << StringToBin(plain) << " (Plain) " << std::endl;

    OneTimePad otp(plain.size());
    std::cout << otp.generateKey() << " (Key) " << std::endl;
    std::cout << otp.encrypt(plain) << " (Cipher) " << std::endl;
    std::cout << otp.decrypt() << " (Original) " << std::endl;
    std::cout << otp.getOriginal() << " (Original String) " << std::endl;

    return 0;
}

/*
010011110110111001100101001000000101010001101001011011010110010100100000010100000110000101100100 (Plain) 
011000110010001101011000011010110010110101010000011100010010110101000010011001100100110001010100 (Key) 
001011000100110100111101010010110111100100111001000111000100100001100010001101100010110100110000 (Cipher) 
010011110110111001100101001000000101010001101001011011010110010100100000010100000110000101100100 (Original) 
One Time Pad (Original String) 
*/