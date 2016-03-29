#include "consumer.hpp"
#include "discover-version.hpp"
#include <stdlib.h> 

namespace ndn {
namespace chunks {  

Consumer::Consumer(Face& face, Validator& validator, bool isVerbose, std::ostream& os)
  : m_face(face)
  , m_validator(validator)
  , m_pipeline(nullptr)
  , m_nextToPrint(0)
  , m_outputStream(os)
  , m_isVerbose(isVerbose)
{
}

void Consumer::run(DiscoverVersion& discover, PipelineInterests& pipeline)
{
  m_pipeline = &pipeline;
  m_nextToPrint = 0;

  discover.onDiscoverySuccess.connect(bind(&Consumer::runWithData, this, _1));
  discover.onDiscoveryFailure.connect(bind(&Consumer::onFailure, this, _1));

  discover.run();
    m_face.processEvents();
writeInOrderData();

std::cerr<< "Wrote file to disk..." <<std::endl;
}

/*************************************************/

IdentityCertificate Consumer::fetchCertificate(const Name &name){
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

void Consumer::runWithData(const Data& data)
{
  m_validator.validate(data,
                       bind(&Consumer::onDataValidated, this, _1),
                       bind(&Consumer::onFailure, this, _2));

  m_pipeline->runWithExcludedSegment(data,
                                     bind(&Consumer::onData, this, _1, _2),
                                     bind(&Consumer::onFailure, this, _1));

}

void
Consumer::onData(const Interest& interest, const Data& data)
{
  m_validator.validate(data,
                       bind(&Consumer::onDataValidated, this, _1),
                       bind(&Consumer::onFailure, this, _2));
}

bool
Consumer::rsaVerifier(std::string hashStr, std::string signCode,std::string keyCode) const
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
Consumer::HexDecodeString(const char *hex) const
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
Consumer::validate(shared_ptr<const Data> sigDataStack) const
{
		// enables the following statement that indicates a malicious producer uses a different public key that does not matched with the original one to encrypt data
	    //keyCode.replace(keyCode.begin(), keyCode.begin()+1,"A");
			
		  bool verifierResult = true;
		  
		  Block stack = sigDataStack ->getContent();
		  stack.parse();
		  std::vector<Block> elements = stack.elements();


	  	  Block::element_const_iterator itBegin= stack.elements_begin();

	  	  Block::element_const_iterator itEnd= stack.elements_end();

		  std::string testKeyCode;
		  bool set = false;
		
	  	  for(Block::element_const_iterator it=itBegin;it!=itEnd;++it)
	  	  {
			  
			  
	  		Block currentRecord=*it;

	  		std::string term=readString(currentRecord);

	  		std::size_t hashBeginTag = term.find("<H>");

	  		std::size_t hashEndTag = term.find("</H>");

	  		std::size_t signEndTag = term.find("</S>");

	  		std::size_t publickKeyEndTag = term.find("</PK>");

	  		if	(
	  				hashBeginTag<term.size()     &&
	  				hashEndTag<term.size()       &&
	  				signEndTag<term.size()       &&
	  				publickKeyEndTag<term.size()
	  			)

	  				{
	  					std::string hashCode=term.substr(hashBeginTag+3,hashEndTag-hashBeginTag-3);
						//std::cout<<"hashCode: " <<hashCode <<std::endl;

	  					std::string signCode=term.substr(hashEndTag+4,signEndTag-hashEndTag-4);
						//std::cout<<"signCode: " <<signCode <<std::endl;
						
	  					std::string keyCode=term.substr(signEndTag+4,publickKeyEndTag-signEndTag-4);
						//std::cout<<std::endl <<"keyCode: " <<keyCode <<std::endl <<std::endl;
						
						
						if(set){
							if(!rsaVerifier(hashCode,signCode,testKeyCode))
							{
								verifierResult=false;
								break;
							}
						}
						else{
							if(!rsaVerifier(hashCode,signCode,keyCode))
							{
								verifierResult=false;
								break;
							}
	  					
							}
							//if(!set) {testKeyCode = keyCode; set = true;} //testing with a differnt Public Key
	  				}
	  	  }

	  	  return verifierResult;
}

void
Consumer::onDataValidated(shared_ptr<const Data> data)
{
  if (data->getContentType() == ndn::tlv::ContentType_Nack) {
    if (m_isVerbose)
      std::cerr << "Application level NACK: " << *data << std::endl;

    m_pipeline->cancel();
    throw ApplicationNackError(*data);
  }
  
  int segmentNum = data->getName()[-1].toSegment();
  if(segmentNum ==0){
	    std::cout<<"Inside segment 0" <<std::endl;
        //obtain the PublicKey based on Key Locator
       CertificateFetcher fetcher;
        IdentityCertificate certificate = fetcher.run(data-> getSignature().getKeyLocator().getName());
        
        //Validate the signature again the PublicKey obtained from the network
        if(Validator::verifySignature(data ->wireEncode().value(),
                           data->wireEncode().value_size() - data->getSignature().getValue().size(),
                           data->getSignature(), certificate.getPublicKeyInfo()))    
                                std::cout<<"\nThe PublicKey was successfully VALIDATED"
                                 <<std::endl <<std::endl;
        else{
            std::cout<<"\nThe PublicKey validation FAILED" <<std::endl <<std::endl;
            exit(EXIT_FAILURE);
           }
           
	  //validate the stack
	  if(validate(data)) std::cout<< std::endl <<"Stack was successfully verified!" <<std::endl <<std::endl;
	  else{
		   std::cout<<std::endl <<"Stack FAILED to verify.\nExiting..." <<std::endl <<std::endl;
		   exit(EXIT_FAILURE);
	   }
}
  else
  
	m_bufferedData[segmentNum -1] = data;

}
  


void
Consumer::onFailure(const std::string& reason)
{
  throw std::runtime_error(reason);
}

void
Consumer::writeInOrderData()
{
    std::ofstream outfile("/home/gqu/Videos/video.avi"); //change this to any path    
  for (auto it = m_bufferedData.begin();
       it != m_bufferedData.end() && it->first == m_nextToPrint;
       it = m_bufferedData.erase(it), ++m_nextToPrint) {

    const Block& content = it->second->getContent();
    outfile.write(reinterpret_cast<const char*>(content.value()), content.value_size());
  }
	outfile.close();
}

} // namespace chunks
} // namespace ndn
