#include "producer.hpp"
#include <stdlib.h>
#include <iostream>

#include "../src/encoding/block-helpers.hpp"
#include "../src/util/crypto.hpp"

#include "../src/security/cryptopp.hpp"

#include <thread> 

using CryptoPP::Integer;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::PSSR;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSA;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::SecByteBlock;
using CryptoPP::SHA1;

namespace ndn {
namespace chunks {

class CertificatePublisher : noncopyable
{
public:
  void
  run(shared_ptr<IdentityCertificate> defaultCertificate)
  {
	certificate = defaultCertificate;
	//std::cout<<"Public key name: " << defaultCertificate->getPublicKeyInfo() <<std::endl;
	//std::cout<<"Publishing with name: " <<defaultCertificate->getName() <<std::endl;
	std::cout<<"Publishing with Fname:" <<defaultCertificate ->getName().getPrefix(5) <<std::endl;
    m_face.setInterestFilter(defaultCertificate ->getName().getPrefix(5),
                             bind(&CertificatePublisher::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&CertificatePublisher::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter& filter, const Interest& interest)
  {
    m_face.put(*certificate); 
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  shared_ptr<IdentityCertificate> certificate;
};

/*************************************************/
void Producer::publishCertificate(){
	CertificatePublisher publisher;
	try {
		publisher.run(m_keyChain.getDefaultCertificate());
	}
	catch (const std::exception& e) {
		std::cerr << "ERROR: " << e.what() << std::endl;
		std::cerr << "Failed to publish default certifcate" <<std::endl;
	}

}


Producer::Producer(const Name& prefix,
                   Face& face,
                   KeyChain& keyChain,
                   const security::SigningInfo& signingInfo,
                   time::milliseconds freshnessPeriod,
                   size_t maxSegmentSize,
                   bool isVerbose,
                   bool needToPrintVersion,
                   std::istream& is)
  : m_face(face)
  , m_keyChain(keyChain)
  , m_signingInfo(signingInfo)
  , m_freshnessPeriod(freshnessPeriod)
  , m_maxSegmentSize(maxSegmentSize)
  , m_isVerbose(isVerbose)
{
  if (prefix.size() > 0 && prefix[-1].isVersion()) {
    m_prefix = prefix.getPrefix(-1);
    m_versionedPrefix = prefix;
  }
  else {
    m_prefix = prefix;
    m_versionedPrefix = Name(m_prefix).appendVersion();
  }

  populateStore(is);

  if (needToPrintVersion)
    std::cout << m_versionedPrefix[-1] << std::endl;

  m_face.setInterestFilter(m_prefix,
                           bind(&Producer::onInterest, this, _2),
                           RegisterPrefixSuccessCallback(),
                           bind(&Producer::onRegisterFailed, this, _1, _2));

  if (m_isVerbose)
    std::cerr << "Data published with name: " << m_versionedPrefix << std::endl;
}

void
Producer::run()
{
  m_face.processEvents();
}

std::string
Producer::termGenerator(const uint8_t* content, size_t contentLength) const
{


	// begin of hash content
		std::string term="<H>";

		using namespace CryptoPP;

      SHA256 hash;
      std::string hashStr;

      StringSource(content, contentLength, true, new HashFilter ( hash,
    		  	  	  	  	  	  	  			  	  	  new HexEncoder (
    		  	  	  	  	  	  	  			  	  			  new StringSink( hashStr )
    		  	  	  	  	  	  	  	  	  	  	  	  	  	  	  	  ) // HexEncoder
      	  	  	  	  	  	  	  	  	  	  	  	  	  ) // hash filter
      	  	  	  	  	  	  	  	  	  );  

		// add hash of current content
		//std::string hashStr=hashToStr(getHashContent());
		term+=hashStr;

		// end of hash
		term+="</H>";

		// RSA encrypted hash based on a private key
	    term+=RSAEnc(hashStr);

		// NOTE: enable malicious data to test an invalidate packet
	//	term+="HHH";

	    // end of encrypted of hash
	    //term+="</PK>";

	    return term;
}

std::string
Producer::RSAEnc(std::string hashStr) const
{
	
	AutoSeededRandomPool rng;

	InvertibleRSAFunction parameters;
	parameters.GenerateRandomWithKeySize(rng, 1536);


	RSA::PrivateKey privateKey(parameters);
	RSA::PublicKey publicKey(parameters);

	// Message
	std::string message = hashStr;

	// Signer object
	CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

	// Create signature space
	size_t length = signer.MaxSignatureLength();
	SecByteBlock signature(length);

	// Sign message
	length = signer.SignMessage(rng, (const byte*) message.c_str(),
	    message.length(), signature);

	// Resize now we know the true size of the signature
	signature.resize(length);

	std::string encoded = "";

	CryptoPP::StringSource ss( signature.data(), signature.size(), true,
	    new CryptoPP::HexEncoder(
	        new CryptoPP::StringSink( encoded )
	    ) // HexEncoder
	); // StringSource

	std::string rsaPubKey;
	CryptoPP::StringSink stringSink(rsaPubKey);
	publicKey.DEREncode(stringSink);

	encoded+="</S>"+rsaPubKey+"</PK>";

	return encoded;
	 
}


void
Producer::onInterest(const Interest& interest)
{
  BOOST_ASSERT(m_store.size() > 0);

  if (m_isVerbose)
    std::cerr << "Interest: " << interest << std::endl;

  const Name& name = interest.getName();
  shared_ptr<Data> data;

  // is this a discovery Interest or a sequence retrieval?
  if (name.size() == m_versionedPrefix.size() + 1 && m_versionedPrefix.isPrefixOf(name) &&
      name[-1].isSegment()) {
    const auto segmentNo = static_cast<size_t>(interest.getName()[-1].toSegment());
    // specific segment retrieval
    if (segmentNo < m_store.size()) {
      data = m_store[segmentNo];
    }
  }
  else if (interest.matchesData(*m_store[0])) {
    // Interest has version and is looking for the first segment or has no version
    data = m_store[0];
  }

  if (data != nullptr) {
    if (m_isVerbose)
      std::cerr << "Data: " << *data << std::endl;

    m_face.put(*data);
  }
}

void
Producer::populateStore(std::istream& is)
{
  BOOST_ASSERT(m_store.size() == 0);
    
    
  if (m_isVerbose)
    std::cerr << "Loading cobmined video file ..." << std::endl;

  std::vector<uint8_t> tempBuffer(m_maxSegmentSize);
  std::vector<uint8_t> fileBuffer;
 
  while (is.good()) {
    is.read(reinterpret_cast<char*>(tempBuffer.data()), tempBuffer.size());
    std::copy(tempBuffer.begin(), tempBuffer.end(), back_inserter(fileBuffer));
    const auto nCharsRead = is.gcount();
    if (nCharsRead > 0) {
        auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(m_store.size() + 1));
        data->setFreshnessPeriod(m_freshnessPeriod);
        data->setContent(&tempBuffer[0], nCharsRead);
        //std::cout<<"Current item: " <<data ->getContent().value() <<std::endl;
      m_store.push_back(data);
    }
  }
    
    
         
   // create signature
  
    const uint8_t* buf = &fileBuffer[0];
    const std::string newTerm =termGenerator(buf, fileBuffer.size());
    
    //std::cout<<"Term is: " <<newTerm <<std::endl;
    
    auto tempData = make_shared<Data>();
    tempData -> setContent(reinterpret_cast<const uint8_t*>(newTerm.c_str()), newTerm.size());                                   
     
    auto data= make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(m_freshnessPeriod);
    
      Block sigBlock(tempData -> getContent());
         
      data ->setContent(sigBlock);
     // std::cout<<"Default identity: " <<m_keyChain.getDefaultIdentity() <<std::endl;
     // std::cout<<"Defualt key BEFORE: " <<m_keyChain.getDefaultCertificate() <<std::endl;
      m_keyChain.generateRsaKeyPairAsDefault(m_keyChain.getDefaultIdentity(),
															   true, 1536);
	  
      // std::cout<<"Defualt key AFTER: " <<m_keyChain.getDefaultCertificate() <<std::endl;
	  //Name aliceKeyName("/ndn/test/alice/ksk-1394129695025");

//shared_ptr<IdentityCertificate> aliceCert = keyChain.selfSign(aliceKeyName);
      
	  //std::cout<<"Default identity: " <<m_keyChain.getDefaultIdentity() <<std::endl;
	  
      m_keyChain.sign(*data);
      
    m_store.insert(m_store.begin(), data);
	
   //Publish default certificate
	std::thread fetcher(std::bind(&Producer::publishCertificate, this));
	fetcher.detach();
	
	

  if (m_store.empty()) {
    auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(m_freshnessPeriod);
    m_store.push_back(data);
  }

  auto finalBlockId = name::Component::fromSegment(m_store.size() - 1);
  for (const auto& data : m_store) {
    data->setFinalBlockId(finalBlockId);
    m_keyChain.sign(*data, m_signingInfo);
  }

  if (m_isVerbose)
    std::cerr << "Created " << m_store.size() << " chunks for prefix " << m_prefix << std::endl;
}

void
Producer::onRegisterFailed(const Name& prefix, const std::string& reason)
{
  std::cerr << "ERROR: Failed to register prefix '"
            << prefix << "' (" << reason << ")" << std::endl;
  m_face.shutdown();
}

} // namespace chunks
} // namespace ndn
