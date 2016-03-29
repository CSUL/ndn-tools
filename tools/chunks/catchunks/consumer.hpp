#ifndef NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP
#define NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP

#include "pipeline-interests.hpp"
#include "discover-version.hpp"

#include <ndn-cxx/security/validator.hpp>
#include <fstream>
#include <iostream>

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
  shared_ptr<const Data>
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
  std::vector<shared_ptr<const Data>> m_store;
  std::ofstream outfile;
  shared_ptr<const Data> m_signature;
  

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<uint64_t, shared_ptr<const Data>> m_bufferedData;
};

} // namespace chunks
} // namespace ndn

#endif // NDN_TOOLS_CHUNKS_CATCHUNKS_CONSUMER_HPP
