#include "pktcap.h"

#include <cassert>
#include <functional>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

// include windows.h first
#include <windows.h>

#include <evntcons.h>
#include <evntrace.h>
#include <in6addr.h>
#include <ndisguid.h>
#include <tdh.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace pktcap {

#pragma pack(push, 1)
struct eth_header {
  uint8_t dst_mac[6];
  uint8_t src_mac[6];
  uint16_t type;
};

struct ip_header {
  uint8_t ver_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;
};

struct tcp_header {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset;
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
};
#pragma pack(pop)

GUID kNdisGuid = {0x2ed6006e,
                  0x4729,
                  0x4609,
                  {0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef}};

class capture {
 public:
  capture(int id, const pktcap::config& config)
      : id_(id), config_(config), exit_(false) {
    thread_ = std::thread(&capture::thread, this);
  }

  ~capture() {
    exit_ = true;
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  inline void packet_cb(const uint8_t* buf,
                        size_t len,
                        const std::string& src_ip,
                        int src_port,
                        const std::string& dst_ip,
                        int dst_port) {
    if (config_.packet_cb) {
      config_.packet_cb(buf, len, src_ip, src_port, dst_ip, dst_port);
    }
  }

  inline void error_cb(const std::string& msg) {
    if (config_.error_cb) {
      config_.error_cb(msg);
    }
  }

  void thread() {
    static wchar_t kLoggerName[] = L"tcpcap";
    TRACEHANDLE session{};
    ULONG status{};

    alignas(EVENT_TRACE_PROPERTIES)
        uint8_t buf[sizeof(EVENT_TRACE_PROPERTIES) + 2048]{};
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)buf;
    props->Wnode.BufferSize = sizeof(buf);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LoggerNameOffset = props->LogFileNameOffset + 1024;

    try {
      status = StartTrace(&session, kLoggerName, props);
      if (status == ERROR_ALREADY_EXISTS) {
        status = ControlTrace(0, kLoggerName, props, EVENT_TRACE_CONTROL_STOP);
        assert(status == 0);

        status = StartTrace(&session, kLoggerName, props);
        assert(status == 0);
      }
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to StartTrace().");
      }

      status = EnableTraceEx2(session, &kNdisGuid,
                              EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                              TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to EnableTraceEx2().");
      }

      // process packets
      static auto callback = [](PEVENT_RECORD ev) {
        assert(ev->UserContext != NULL);
        capture* self = static_cast<capture*>(ev->UserContext);
        self->process_packet(ev);
      };
      EVENT_TRACE_LOGFILE logfile{};
      logfile.LoggerName = kLoggerName;
      logfile.ProcessTraceMode =
          PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
      logfile.Context = this;
      logfile.EventRecordCallback = callback;
      TRACEHANDLE tracehandle = OpenTrace(&logfile);
      if (tracehandle == INVALID_PROCESSTRACE_HANDLE) {
        throw std::runtime_error("failed to OpenTrace().");
      }

      status = ProcessTrace(&tracehandle, 1, nullptr, nullptr);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to ProcessTrace().");
      }

      status =
          ControlTrace(session, kLoggerName, props, EVENT_TRACE_CONTROL_STOP);
    } catch (std::exception& ex) {
      error_cb(ex.what());
      if (session != NULL) {
        status =
            ControlTrace(session, kLoggerName, props, EVENT_TRACE_CONTROL_STOP);
      }
    }
  }

  void process_packet(PEVENT_RECORD ev) {
    if (ev->EventHeader.ProviderId != kNdisGuid) {
      return;
    }

    const auto& ed = ev->EventHeader.EventDescriptor;
    if ((ed.Version << 16 | ed.Id) != 1001) {
      // packet fragment
      return;
    }

    const uint8_t* buf = (uint8_t*)ev->UserData;

    uint32_t miniport_if = *(uint32_t*)(buf + 0);
    uint32_t lower_if = *(uint32_t*)(buf + 4);
    uint32_t fragment_size = *(uint32_t*)(buf + 8);
    const uint8_t* fragment = buf + 12;

    const eth_header* eth = (eth_header*)fragment;
    if (htons(eth->type) != 0x0800) {
      // ipv4
      return;
    }

    const ip_header* ip = (ip_header*)(fragment + sizeof(eth_header));
    unsigned char ip_hdr_version = (ip->ver_ihl & 0xf0) >> 4;
    unsigned char ip_hdr_size = (ip->ver_ihl & 0x0f) * 4;
    if (ip->protocol != 0x06) {
      // tcp
      return;
    }

    const tcp_header* tcp = (tcp_header*)(fragment + ip_hdr_size);
    uint8_t tcp_hdr_size = (tcp->data_offset >> 4) * 4;
    if (fragment_size < (uint32_t)(ip_hdr_size + tcp_hdr_size)) {
      return;
    }

    const uint8_t* payload = fragment + ip_hdr_size + tcp_hdr_size;
    size_t payload_length = fragment_size - ip_hdr_size - tcp_hdr_size;

    in_addr src_addr, dst_addr;
    src_addr.S_un.S_addr = ip->src_addr;
    dst_addr.S_un.S_addr = ip->dst_addr;
    std::string src_ip = inet_ntoa(src_addr);
    std::string dst_ip = inet_ntoa(dst_addr);
    std::string src_port = std::to_string(htons(tcp->src_port));
    std::string dst_port = std::to_string(htons(tcp->dst_port));

    // check allow
    auto get_source = [&](const pktcap::rule& r) -> const std::string& {
      if (r.dir == rule::src) {
        if (r.source == rule::port) {
          return src_port;
        } else if (r.source == rule::ip) {
          return src_ip;
        }
      } else if (r.dir == rule::dst) {
        if (r.source == rule::port) {
          return dst_port;
        } else if (r.source == rule::ip) {
          return dst_ip;
        }
      }
      throw std::runtime_error("unexpected rule.");
    };

    bool drop = false;
    drop |= (!config_.rules.empty()) &&
            std::all_of(
                config_.rules.begin(), config_.rules.end(), [&](const auto& r) {
                  if (r.type != rule::allow) {
                    std::string source = get_source(r);
                    if (r.pattern && !std::regex_match(source, *r.pattern)) {
                      return true;
                    }
                  }
                  return false;
                });
    drop |= std::any_of(
        config_.rules.begin(), config_.rules.end(), [&](const auto& r) {
          if (r.type == rule::deny) {
            std::string source = get_source(r);
            if (!r.pattern || std::regex_match(source, *r.pattern)) {
              return true;
            }
          }
          return false;
        });
    if (drop) {
      return;
    }

    packet_cb(payload, payload_length, src_ip, std::stoi(src_port), dst_ip,
              std::stoi(dst_port));
  }

  int id() const { return id_; }
  const pktcap::config& config() const { return config_; }

 private:
  std::atomic_bool exit_;
  int id_;
  pktcap::config config_;
  std::thread thread_;
};

std::unordered_map<int, std::unique_ptr<capture>> g_captures;
std::mutex g_mutex;

int start_capture(config& config) {
  std::lock_guard lock(g_mutex);
  static int id = 0;
  std::unique_ptr<capture> instance(new capture(id++, config));
  g_captures[id] = std::move(instance);
  return id;
}

void stop_capture(int id) {
  std::lock_guard lock(g_mutex);
  if (g_captures.contains(id)) {
    g_captures.erase(id);
  }
}

}  // namespace pktcap
