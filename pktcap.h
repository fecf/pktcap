#pragma once

#include <functional>
#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace pktcap {

struct rule {
  enum { allow, deny } type;
  enum { port, ip } source;
  enum { src, dst } dir;
  std::optional<std::regex> pattern;
};

struct config {
  enum {
    raw,
    ndis,
  } method = raw;

  // allow all packets by default and
  // evaluate in the order of deny, allow
  std::vector<rule> rules;

  std::optional<std::regex> network;

  std::function<void(const uint8_t*,
                     size_t,
                     const std::string&,
                     int,
                     const std::string&,
                     int)>
      packet_cb;
  std::function<void(const std::string&)> error_cb;
};

int start_capture(config& config);
void stop_capture(int id);

}  // namespace pktcap
