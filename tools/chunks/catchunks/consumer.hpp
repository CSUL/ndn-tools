/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2016,  Regents of the University of California,
 *                      Colorado State University,
 *                      University Pierre & Marie Curie, Sorbonne University.
 *
 * This file is part of ndn-tools (Named Data Networking Essential Tools).
 * See AUTHORS.md for complete list of ndn-tools authors and contributors.
 *
 * ndn-tools is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-tools is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-tools, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Wentao Shang
 * @author Steve DiBenedetto
 * @author Andrea Tosatto
 */


#ifndef NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP
#define NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP

#include "pipeline-interests.hpp"
#include "discover-version.hpp"

#include <ndn-cxx/security/validator.hpp>
#include <fstream>

#include "src/encoding/block-helpers.hpp"
#include "src/util/crypto.hpp"

#include "src/security/cryptopp.hpp"

//#include <src/cryptopp/integer.h>
using CryptoPP::Integer;

//#include <src/cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

//#include <src/cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

//#include <src/cryptopp/pssr.h>
using CryptoPP::PSSR;

//#include <src/cryptopp/rsa.h>
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSA;

//#include <src/cryptopp/cryptlib.h>

using CryptoPP::Exception;
using CryptoPP::DecodingResult;

//#include <src/cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

//#include <src/cryptopp/sha.h>
using CryptoPP::SHA1;
namespace ndn {
namespace chunks {

/**
 * @brief Segmented version consumer
 *
 * Discover the latest version of the data published under a specified prefix, and retrieve all the
 * segments associated to that version. The segments are fetched in order and written to a
 * user-specified stream in the same order.
 */
class Consumer : noncopyable
{
public:
  class ApplicationNackError : public std::runtime_error
  {
  public:
    explicit
    ApplicationNackError(const Data& data)
      : std::runtime_error("Application generated Nack: " + boost::lexical_cast<std::string>(data))
    {
    }
  };

  /**
   * @brief Create the consumer
   */
  Consumer(Face& face, Validator& validator, bool isVerbose, std::ostream& os = std::cout);

  /**
   * @brief Run the consumer
   */
  void
  run(DiscoverVersion& discover, PipelineInterests& pipeline);

private:
  void
  runWithData(const Data& data);

  void
  onData(const Interest& interest, const Data& data);

  void
  onDataValidated(shared_ptr<const Data> data);

  void
  onFailure(const std::string& reason);
  
  bool
  validate(shared_ptr<const Data> sigDataStack) const;
  
  bool
  rsaVerifier(std::string hashStr, std::string signCode,std::string keyCode) const;
  
  IdentityCertificate 
  fetchCertificate(const Name &name);
  
  CryptoPP::SecByteBlock
  HexDecodeString(const char *hex) const;
  
PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  writeInOrderData();

private:
  Face& m_face;
  Validator& m_validator;
  PipelineInterests* m_pipeline;
  uint64_t m_nextToPrint;
  std::ostream& m_outputStream;
  bool m_isVerbose;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<uint64_t, shared_ptr<const Data>> m_bufferedData;
  
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

#endif // NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP
