#include "consumer.hpp"
#include "discover-version.hpp"
//#include "../putchunks/producer.hpp"
#include "core/common.hpp"
#include <vector>
#include <fstream>
#include "city-hash.hpp"




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

shared_ptr<const Data> Consumer::run(DiscoverVersion& discover, PipelineInterests& pipeline)
{
  
  m_pipeline = &pipeline;
  m_nextToPrint = 0;

  discover.onDiscoverySuccess.connect(bind(&Consumer::runWithData, this, _1));
  discover.onDiscoveryFailure.connect(bind(&Consumer::onFailure, this, _1));
	
  discover.run();
  m_face.processEvents();
  
  writeInOrderData();
  return m_signature;

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

void
Consumer::onDataValidated(shared_ptr<const Data> data)
{
  if (data->getContentType() == ndn::tlv::ContentType_Nack) {
    if (m_isVerbose)
      std::cerr << "Application level NACK: " << *data << std::endl;

    m_pipeline->cancel();
    throw ApplicationNackError(*data);
  }
	
  //populate temporary storage with the data received
  int segmentNum = data->getName()[-1].toSegment();
  if(segmentNum ==0){ 
	m_signature = data;
	Block content = data -> getContent();
	content.parse();
	std::cout<<"Got signature block with size is: " <<content.elements_size()  <<std::endl;
}
  else{
	
	m_bufferedData[segmentNum -1] = data;
}


}

void
Consumer::onFailure(const std::string& reason)
{
  throw std::runtime_error(reason);
}


void
Consumer::writeInOrderData()
{
	
	
    
	int status = system("mkdir -p /tmp/temp_videos");
	if(status == -1){
		std::cerr<<"Failed to make temp folder" <<std::endl;
	}
	else
		std::cout<<"Created folder \"temp_videos\"..." <<std::endl; 
	std::ofstream outfile ("/tmp/temp_videos/video.mp4",std::ofstream::binary);
	
       
  for (auto it = m_bufferedData.begin();
       it != m_bufferedData.end() && it->first == m_nextToPrint;
       it = m_bufferedData.erase(it), ++m_nextToPrint) {

        
 const Block& content = it->second->getContent();

  outfile.write(reinterpret_cast<const char*>(content.value()), content.value_size()); 
  
  

  }
  

}

} // namespace chunks
} // namespace ndn
