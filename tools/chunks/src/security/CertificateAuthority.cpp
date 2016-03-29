/*
 * CertificateAuthority.cpp
 *
 *  Created on: Mar 7, 2016
 *      Author: mbahrami
 */

#include "CertificateAuthority.hpp"


namespace ndn {

namespace security {

/*
CertificateAuthority::CertificateAuthority() {
	// TODO Auto-generated constructor stub

}

CertificateAuthority::~CertificateAuthority() {
	// TODO Auto-generated destructor stub
}
*/


Block
CertificateAuthority::localSign(const Name& dataName, KeyChain& keyChain, const uint8_t* originalContent, const size_t originalLen)
{
	Block sigBlock;

	if(getLocalPublicKeyOfDataName(dataName, keyChain))
	{
		sigBlock = keyChain.getTpm().signInTpm(originalContent, originalLen,
	                										dataName, DIGEST_ALGORITHM_SHA256);
	}

	return sigBlock;
}

shared_ptr<PublicKey>
CertificateAuthority::getLocalPublicKeyOfDataName(const Name& dataName, KeyChain& keyChain)
{

	//	RsaKeyParams params(2048);

	//	if(!keyChain.getTpm().doesKeyExistInTpm(dataName,KeyClass::KEY_CLASS_PUBLIC))
	//		keyChain.getTpm().generateKeyPairInTpm(dataName,params);

	return(keyChain.getTpm().getPublicKeyFromTpm(dataName));
}

/// verify a signature
bool
CertificateAuthority::verify(const uint8_t* originalContent, const size_t originalLen, const Block& sigBlock, shared_ptr<PublicKey> publicKey )
{
	bool result=false;

    using namespace CryptoPP;

    RSA::PublicKey rsaPublicKey;

    ByteQueue queue;

    queue.Put(reinterpret_cast<const byte*>(publicKey->get().buf()), publicKey->get().size());
    rsaPublicKey.Load(queue);

    /// fake hash
    //const uint8_t fakeHashContent[] = {0x02, 0x02, 0x03, 0x04};

   RSASS<PKCS1v15, SHA256>::Verifier verifier(rsaPublicKey);

   result = verifier.VerifyMessage(originalContent, originalLen,
                                               sigBlock.value(), sigBlock.value_size());

   //keyChain.getTpm().deleteKeyPairInTpm(dataName);

    return result;
}

const std::string
CertificateAuthority::getStrHash(const uint8_t* content, size_t contentLength)
{
	std::string hashContent = crypto::sha256Str(content, contentLength);

	return hashContent;

}

const uint8_t*
CertificateAuthority::convertToUint(const std::string content)
{
const uint8_t* newContent=reinterpret_cast<const uint8_t*>(content.c_str());

	 return newContent;
}



} //security

}// ndn


