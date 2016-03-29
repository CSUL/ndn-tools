

/*
 * CertificateAuthority.hpp
 *
 *  Created on: Mar 7, 2016
 *      Author: Mehdi bahrami
 *      @ Fujitsu Laboratory of America (FLA), Ltd.
 */


#ifndef NDN_SECURITY_CERTIFICATEAUTHORITY_HPP_
#define NDN_SECURITY_CERTIFICATEAUTHORITY_HPP_


#include "security/key-chain.hpp"
#include "security/validator-null.hpp"

#include "security/sec-public-info.hpp"

#include "security/sec-tpm-file.hpp"
#include "security/cryptopp.hpp"

#include "sec-public-info.hpp"
#include "sec-tpm.hpp"
#include "key-params.hpp"
#include "secured-bag.hpp"
#include "signature-sha256-with-rsa.hpp"
#include "signature-sha256-with-ecdsa.hpp"
#include "digest-sha256.hpp"
#include "signing-info.hpp"

#include "../interest.hpp"
#include "../util/crypto.hpp"
#include "../util/random.hpp"

namespace ndn {


namespace security {

class CertificateAuthority {
public:
//	CertificateAuthority();

//	virtual ~CertificateAuthority();
Block
localSign(const Name& dataName, KeyChain& keyChain, const uint8_t* originalContent, const size_t originalLen);

bool
verify(const uint8_t* originalContent, const size_t originalLen, const Block& sigBlock, shared_ptr<PublicKey> publicKey );

shared_ptr<PublicKey>
getLocalPublicKeyOfDataName(const Name& dataName, KeyChain& keyChain);

const std::string
getStrHash(const uint8_t* content, size_t contentLength);

const uint8_t*
convertToUint(const std::string content);

private:
Name m_publicKeyName;
shared_ptr<IdentityCertificate> m_certificate;
bool m_verficationStatus;

};  // CertificateAuthority class

} // security


} // ndn

#endif /* CERTIFICATEAUTHORITY_HPP_ */
