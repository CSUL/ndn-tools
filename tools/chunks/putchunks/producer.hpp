#ifndef NDN_TOOLS_CHUNKS_PUTCHUNKS_PRODUCER_HPP
#define NDN_TOOLS_CHUNKS_PUTCHUNKS_PRODUCER_HPP

#include "core/common.hpp"
#include <stdlib.h>



namespace ndn {
namespace chunks {

/**
 * @brief Segmented version Producer
 *
 * Packetizes and publishes data from an input stream under /prefix/<version>/<segment number>.
 * The current time is used as the version number. The store has always at least one element (also
 * with empty input stream).
 */
class Producer : noncopyable
{
public:
  /**
   * @brief Create the Producer
   *
   * @prefix prefix used to publish data, if the last component of prefix is not a version number
   *         the current time is used as version number.
   */
  Producer(const Name& prefix, Face& face, KeyChain& keyChain,
           const security::SigningInfo& signingInfo, time::milliseconds freshnessPeriod,
           size_t maxSegmentSize, bool isVerbose = false, bool needToPrintVersion = false,
           std::istream& is = std::cin);

  /**
   * @brief Run the Producer
   */
  void
  run();

private:
  void
  onInterest(const Interest& interest);

  /**
   * @brief Split the input stream in data packets and save them to the store
   *
   * Create data packets reading all the characters from the input stream until EOF, or an
   * error occurs. Each data packet has a maximum payload size of m_maxSegmentSize value and is
   * stored inside the vector m_store. An empty data packet is created and stored if the input
   * stream is empty.
   *
   * @return Number of data packets contained in the store after the operation
   */

  void
  populateStore(std::istream& is);

  void
  onRegisterFailed(const Name& prefix, const std::string& reason);
  
  void
  getData(const Name& name);
  
  void 
  parseInterest(const Name name);
  
  std::string
  RSAEnc(std::string hashStr) const;
  
  std::string
  termGenerator(const uint8_t* content, size_t contentLength) const;
  
  void 
  publishCertificate();
  
  IdentityCertificate 
  fetchCertificate(const Name &name);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::vector<shared_ptr<Data>> m_store;

private:
  Name m_prefix;
  Name m_versionedPrefix;
  Face& m_face;
  KeyChain& m_keyChain;
  security::SigningInfo m_signingInfo;
  time::milliseconds m_freshnessPeriod;
  size_t m_maxSegmentSize;
  bool m_isVerbose;
  bool m_running = false;
  bool m_compressed = false;
  std::string m_newInterestName;
  std::string m_oldInterestName;
  std::vector<shared_ptr< Data>> m_prevNodeSig;
  
  class CertificatePublisher : noncopyable
{
public:
  void
  run(shared_ptr<IdentityCertificate> defaultCertificate)
  {
    certificate = defaultCertificate;
    std::cout<<"Public key name: " << defaultCertificate->getPublicKeyInfo() <<std::endl;
    //std::cout<<"Publishing with name: " <<defaultCertificate->getName() <<std::endl;
    std::cout<<"Publishing with Fname:" <<defaultCertificate->getName().getPrefix(5) <<std::endl;
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
};//CertificatePublisher

class CertificateFetcher : noncopyable
{
public:
  IdentityCertificate
  run(const Name &name)
  {
    Interest interest(name);
    interest.setInterestLifetime(time::milliseconds(2000));
    interest.setMustBeFresh(true);

    m_face.expressInterest(interest,
                           bind(&CertificateFetcher::onData, this,  _1, _2),
                           bind(&CertificateFetcher::onTimeout, this, _1));

    std::cout << "Fetching certificate... " << interest << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();
    return certificate;
  }

private:
  void
  onData(const Interest& interest, const Data& data)
  {
    std::cout<<"Got certificate" <<std::endl <<std::endl;
    std::cout<<data <<std::endl;
    certificate = static_cast<IdentityCertificate>(data);
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout <<std::endl << "FAILED to get certificate " << interest << std::endl <<std::endl;
  }

private:
  Face m_face;
  IdentityCertificate certificate;
};//CertificateFetcher

};

} // namespace chunks
} // namespace ndn

#endif // NDN_TOOLS_CHUNKS_PUTCHUNKS_PRODUCER_HPP
