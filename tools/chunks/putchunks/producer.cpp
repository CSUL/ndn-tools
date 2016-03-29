#include "producer.hpp"
#include "../catchunks/consumer.hpp"
#include "../catchunks/discover-version.hpp"
#include "../catchunks/discover-version.cpp"
#include "../catchunks/options.hpp"
#include "../catchunks/options.cpp"
#include "../catchunks/consumer.cpp"

#include "../catchunks/discover-version-iterative.hpp"
#include "../catchunks/discover-version-iterative.cpp"
#include "../catchunks/pipeline-interests.cpp"
#include "../catchunks/pipeline-interests.hpp"
#include "../catchunks/data-fetcher.cpp"
#include "../catchunks/data-fetcher.hpp"

#include <ndn-cxx/security/validator-null.hpp> 
#include <string>

#include <thread>


namespace ndn {
namespace chunks {

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

/*************************************************/
IdentityCertificate Producer::fetchCertificate(const Name &name){
	 CertificateFetcher fetcher;
	 IdentityCertificate certificate;
    try {
        certificate= fetcher.run(name);
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        std::cerr << "Failed to publish default certifcate" <<std::endl;
    }
    return certificate;

}


 std::vector<shared_ptr<const Data>> Producer::getData(const Name& name){
	//Build interest
         std::cout << "Fetching data for: " <<name <<std::endl;
	std::vector<shared_ptr< const Data>> temp_store;
     	try {
	Options options;
	int maxRetriesAfterVersionFound(0);
	size_t maxPipelineSize(1);
	options.interestLifetime = ndn::DEFAULT_INTEREST_LIFETIME;
	options.maxRetriesOnTimeoutOrNack = -1;
	options.mustBeFresh = true;
    	Face face;

    	unique_ptr<DiscoverVersion> discover;
   	 
   	  DiscoverVersionIterative::Options optionsIterative(options);
    	  optionsIterative.maxRetriesAfterVersionFound = maxRetriesAfterVersionFound;
    	  discover = make_unique<DiscoverVersionIterative>(name, face, optionsIterative);

    ValidatorNull validator;
    Consumer consumer(face, validator, options.isVerbose);

    PipelineInterests::Options optionsPipeline(options);
    optionsPipeline.maxPipelineSize = maxPipelineSize;
    PipelineInterests pipeline(face, optionsPipeline);

    BOOST_ASSERT(discover != nullptr);
	
	
    m_prevNodeSig.push_back(std::const_pointer_cast<Data>(consumer.run(*discover, pipeline)));
    
  }
  catch (const Consumer::ApplicationNackError& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;

  }
  std::cout << "Got data for: " <<name <<std::endl;
  return temp_store;
}


void Producer::parseInterest(const Name name){
        std::stringstream buffer;
        buffer <<name << std::endl;
        m_oldInterestName = buffer.str();
        
        buffer.str("");
        buffer <<m_versionedPrefix[-1];
        m_versionedPrefix = Name(m_oldInterestName + "/" + buffer.str());

        int firstPos = m_oldInterestName.find_first_of("%3C-");
        m_newInterestName = m_oldInterestName.substr(firstPos+4, 21);
   
        m_numberOfAngles = (int)m_oldInterestName.at(m_oldInterestName.length()-2) - '0';
      
       
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

bool
Producer::rsaVerifier(std::string hashStr, std::string signCode,std::string keyCode) const
{
	SecByteBlock signature;

    try{


	signature=HexDecodeString(signCode.c_str());


	InvertibleRSAFunction parameters;


	RSA::PublicKey rsaPublic;

	CryptoPP::StringSource stringSource(keyCode, true);

	rsaPublic.BERDecode(stringSource);


	CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(rsaPublic);

	bool result = verifier.VerifyMessage((const byte*)hashStr.c_str(),
	    hashStr.length(), signature, signature.size());

	// Result
	if(true == result) {
	    return true;
	} else {
	    return false;
	}
    }
    catch (int e)
    {
    	return false;
    }
}

CryptoPP::SecByteBlock
Producer::HexDecodeString(const char *hex) const
 {
	try
	{
	CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder);
    SecByteBlock result((size_t)ss.MaxRetrievable());
    ss.Get(result, result.size());
    return result;
	}
	catch (int e)
	{
		SecByteBlock result2;
		return result2;
	}
}

bool
Producer::validate(IdentityCertificate certificate) const
{		  std::cout<<"Inside validate" <<std::endl;
          bool verifierResult = true;
		 std::string rsaPubKey = readString(certificate.getPublicKeyInfo().computeDigest());
		 std::cout<<"passed" <<std::endl;
		  //CryptoPP::StringSink stringSink(rsaPubKey);
		  //publicKey.DEREncode(stringSink);
		  CryptoPP::StringSource ss(rsaPubKey, true);
		  RSA::PublicKey publicKey;
		  publicKey.Load(ss);
		  
		  std::string pk;
		  CryptoPP::StringSink stringSink(pk);
		  publicKey.DEREncode(stringSink);
		  
		  std::cout<<"\n\nPUB KEY: " <<pk <<"\n\n";
		
                            if(!rsaVerifier(readString(certificate.getContent()),
                                             readString(certificate.getSignature().getValue()),
                                             pk))
                            {
                                verifierResult=false;
                                
                            }

            return verifierResult;
}



void
Producer::onInterest(const Interest& interest)
{
	const Name& name = interest.getName();
	
  
  
  if(!m_running){
   m_running = true;
   parseInterest(name);
   std::cout<<"Requested name: " <<name <<std::endl;
   
   //get data for the specified angles
   for(unsigned int i = 0; i < m_numberOfAngles; i++){
	   getData(Name(m_newInterestName + "/Area" + static_cast<char>(65 + i)));
   }
   
   std::cout<<"Combining..." <<std::endl;
   int status = system("ffmpeg -f concat -i /tmp/tmp_videos/file_paths -c copy /tmp/tmp_videos/concat.mp4");
   if(status == -1){
	    std::cerr<<"Failed to combine the video files" <<std::endl;
	    exit (EXIT_FAILURE);
	}
   std::ifstream combined_video ("/tmp/tmp_videos/concat.mp4", std::ios::in|std::ios::binary);
   
	populateStore(combined_video);
	//delete videos temp folder
  int st = system("rm -rf /tmp/tmp_videos");
   if(st == -1) {
	   std::cerr<<"Failed to delete temp folder" <<std::endl;
	   exit (EXIT_FAILURE);
   }
   }

if(m_combined){ 

//respond with data

	shared_ptr<const Data> data;

   //is this a discovery Interest or a sequence retrieval?
  if (name.size() == m_versionedPrefix.size() + 1 && m_versionedPrefix.isPrefixOf(name) &&
      name[-1].isSegment()) {
    const auto segmentNo = static_cast<size_t>(interest.getName()[-1].toSegment());
    // specific segment retrieval
    if (segmentNo < m_store.size()) {
      data = m_store[segmentNo];
    }
    if(segmentNo == m_store.size()-1){
		m_running = false;
		m_combined = false;
		m_prevNodeSig.clear();
		m_store.clear();
	}
  }
  else if(interest.matchesData(*m_store[0])) {
    // Interest has version and is looking for the first segment or has no version
    data = m_store[0];
  }

  if (data != nullptr) {
    if (m_isVerbose)
      std::cerr << "Data: " << *data << std::endl;
    m_face.put(*data);
    
  }
}

}



void
Producer::populateStore(std::ifstream& is)
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
	
	
		
	
	//create own signature
    const uint8_t* buf = &fileBuffer[0];
    const std::string newTerm =termGenerator(buf, fileBuffer.size());
    
    //std::cout<<"Term is: " <<newTerm <<std::endl;
    
    auto tempData = make_shared<Data>();
    tempData -> setContent(reinterpret_cast<const uint8_t*>(newTerm.c_str()), newTerm.size());                                   
     
    auto data= make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(m_freshnessPeriod);
    
      Block sigBlock(tempData -> getContent());
      sigBlock.push_back(tempData -> getContent());
     
     std::cout<<"Got signature block with size: " <<m_prevNodeSig.size() <<std::endl;
     
      //copy previos node signature
     for(unsigned int i = 0; i< m_prevNodeSig.size(); i++){
		const shared_ptr<Data> data = m_prevNodeSig[i];
        Block content = data-> getContent();
         
        //obtain the PublicKey based on Key Locator
        
        //std::cout<<"\n\nKEY DIGEST: " <<data-> getSignature().getKeyLocator().wireEncode().value() <<"\n\n";
       // exit(EXIT_SUCCESS); //test
        IdentityCertificate certificate = fetchCertificate(data-> getSignature().getKeyLocator().getName());
		
		//Validate the signature against the PublicKey(Certificate) obtained from the network
		/*Certificate version is ignored*/
        if(Validator::verifySignature(data ->wireEncode().value(),
                           data->wireEncode().value_size() - data->getSignature().getValue().size(),
                           data->getSignature(), certificate.getPublicKeyInfo()))	
								std::cout<<"\nThe PublicKey was successfully VALIDATED for Data pacekt #" <<i+1 
								 <<std::endl <<std::endl;
        else 
			std::cout<<"\nThe PublicKey validation FAILED for Data pacekt #"  <<i+1 <<std::endl <<std::endl;
        
        sigBlock.push_back(content);  
    }
   // exit(EXIT_SUCCESS); //test
		
      data ->setContent(sigBlock);
      m_keyChain.sign(*data);
      
    m_store.insert(m_store.begin(), data);
	
	//Publish default certificate
    std::thread fetcher(std::bind(&Producer::publishCertificate, this));
    fetcher.detach();
    
    
  
  if (m_store.empty()) {
	  std::cout<<"" <<std::endl <<std::endl;
	  std::cerr<<"m_store is EMTPY!" <<std::endl <<std::endl <<std::endl;
    auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(m_freshnessPeriod);
    m_store.push_back(data);
  }

  auto finalBlockId = name::Component::fromSegment(m_store.size() - 1);
  for (const auto& data : m_store) {
    data->setFinalBlockId(finalBlockId);
    m_keyChain.sign(*data, m_signingInfo);
  }
 

	m_combined = true;
	
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
