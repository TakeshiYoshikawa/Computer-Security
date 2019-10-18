#include <iostream>
#include <string>
#include <cstdlib>
#include <cryptopp/modes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/des.h>
#include <cryptopp/des.h>
#include <cryptopp/secblock.h>
#include <algorithm>

int main(){
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::SecByteBlock key(CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
	CryptoPP::SecByteBlock key2(CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH);
	CryptoPP::byte iv[CryptoPP::DES_EDE3::BLOCKSIZE];

	prng.GenerateBlock(key, key.size());

	std::copy(key.begin(), key.end(), key2.begin());
	key2[0] = 1;

	prng.GenerateBlock(iv, sizeof(iv));

	std::string plain = "CBC Mode Test";
	std::string cipher, cipher2, encoded, encoded2, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	CryptoPP::StringSource(key, key.size(), true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) // HexEncoder
	); // StringSource

	encoded2.clear();
	CryptoPP::StringSource(key2, key2.size(), true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	
	std::cout << "key:  " << encoded << std::endl;
	std::cout << "key2: " << encoded2 << std::endl;
	
	// Pretty print iv
	encoded.clear();
	CryptoPP::StringSource(iv, sizeof(iv), true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) // HexEncoder
	); // StringSource
	std::cout << "iv: " << encoded << std::endl;

	/*********************************\
	\*********************************/

	try{
		std::cout << "plain text: " << plain << std::endl;

		CryptoPP::CBC_Mode< CryptoPP::DES_EDE3 >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		CryptoPP::CBC_Mode< CryptoPP::DES_EDE3 >::Encryption e2;
		e2.SetKeyWithIV(key2, key2.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		CryptoPP::StringSource(plain, true, 
			new CryptoPP::StreamTransformationFilter(e,
				new CryptoPP::StringSink(cipher)
			)        
		);

		CryptoPP::StringSource(plain, true, 
			new CryptoPP::StreamTransformationFilter(e,
				new CryptoPP::StringSink(cipher2)
			)        
		);
	}
	catch(const CryptoPP::Exception& e)
	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	CryptoPP::StringSource(cipher, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		) // HexEncoder
	); // StringSource
	std::cout << "cipher text: " << encoded << std::endl;

	encoded2.clear();
	CryptoPP::StringSource(cipher2, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	std::cout << "cipher text: " << encoded2 << std::endl;
	/*********************************\
	\*********************************/

	try{
		CryptoPP::CBC_Mode< CryptoPP::DES_EDE3 >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes padding as required.
		CryptoPP::StringSource s(cipher, true, 
			new CryptoPP::StreamTransformationFilter(d,
				new CryptoPP::StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		std::cout << "recovered text: " << recovered << std::endl;
	}
	catch(const CryptoPP::Exception& e)	{
		std::cerr << e.what() << std::endl;
		exit(1);
	}
	return 0;
}

