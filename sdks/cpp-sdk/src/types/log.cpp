// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/types/log.hpp"

namespace quantaureum {

// LogFilter::Builder implementation
LogFilter::Builder& LogFilter::Builder::fromBlock(const std::string& block) {
    filter_.fromBlock = block;
    return *this;
}

LogFilter::Builder& LogFilter::Builder::fromBlock(uint64_t block) {
    filter_.fromBlock = "0x" + Uint256(block).toHex().substr(2);
    return *this;
}

LogFilter::Builder& LogFilter::Builder::toBlock(const std::string& block) {
    filter_.toBlock = block;
    return *this;
}

LogFilter::Builder& LogFilter::Builder::toBlock(uint64_t block) {
    filter_.toBlock = "0x" + Uint256(block).toHex().substr(2);
    return *this;
}

LogFilter::Builder& LogFilter::Builder::address(const Address& addr) {
    filter_.addresses.push_back(addr);
    return *this;
}

LogFilter::Builder& LogFilter::Builder::addresses(const std::vector<Address>& addrs) {
    filter_.addresses.insert(filter_.addresses.end(), addrs.begin(), addrs.end());
    return *this;
}

LogFilter::Builder& LogFilter::Builder::topic0(const Hash& topic) {
    if (filter_.topics.empty()) filter_.topics.resize(1);
    filter_.topics[0] = topic;
    return *this;
}

LogFilter::Builder& LogFilter::Builder::topic1(const Hash& topic) {
    while (filter_.topics.size() < 2) filter_.topics.push_back(std::nullopt);
    filter_.topics[1] = topic;
    return *this;
}

LogFilter::Builder& LogFilter::Builder::topic2(const Hash& topic) {
    while (filter_.topics.size() < 3) filter_.topics.push_back(std::nullopt);
    filter_.topics[2] = topic;
    return *this;
}

LogFilter::Builder& LogFilter::Builder::topic3(const Hash& topic) {
    while (filter_.topics.size() < 4) filter_.topics.push_back(std::nullopt);
    filter_.topics[3] = topic;
    return *this;
}

LogFilter LogFilter::Builder::build() {
    return filter_;
}

LogFilter::Builder LogFilter::builder() {
    return Builder();
}

} // namespace quantaureum
