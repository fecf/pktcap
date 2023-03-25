#include "pktcap.h"

#include <cassert>
#include <functional>
#include <iostream>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <format>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>

#include <evntcons.h>
#include <evntrace.h>
#include <in6addr.h>
#include <ndisguid.h>
#include <tdh.h>
#include <iphlpapi.h>
#include <iptypes.h>

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
    constexpr int max_retry = 3;
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)::malloc(buflen);
    for (int iter = 0; iter < max_retry; iter++) {
      DWORD ret = ::GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &buflen);
      if (ret == ERROR_BUFFER_OVERFLOW) {
        ::free(addresses);
        addresses = NULL;
      } else if (ret != NO_ERROR) {
        error_cb("failed to GetAdaptersAddresses().");
        continue;
      }
    }

    for (; addresses != NULL; addresses = addresses->Next) {
      MIB_IFROW row{};
      row.dwIndex = addresses->IfIndex;
      DWORD ret = ::GetIfEntry(&row);
      if (ret != NO_ERROR) {
        error_cb(std::format("failed to GetIfEntry(). code:{}", ret));
        continue;
      }

      nic& nic = nic_[addresses->IfIndex];
      nic.row = row;

      for (int i = 0; i < 6; i++) {
        nic.mac[i] = 0x00;
      }
      if (addresses->PhysicalAddressLength != NULL) {
        for (int i = 0; i < (int)addresses->PhysicalAddressLength; i++) {
          nic.mac[i] = addresses->PhysicalAddress[i];
        }
      }

      PIP_ADAPTER_UNICAST_ADDRESS unicast = addresses->FirstUnicastAddress;
      for (; unicast != NULL; unicast = unicast->Next) {
        auto* addr = unicast->Address.lpSockaddr;
        char buf[1024];
        PCSTR ret = NULL;
        if (addr->sa_family == AF_INET) {
          auto* sin_addr = &((sockaddr_in*)addr)->sin_addr;
          ret = inet_ntop(AF_INET, sin_addr, buf, sizeof(buf));
        } else if (addr->sa_family == AF_INET6) {
          auto* sin6_addr = &((sockaddr_in6*)addr)->sin6_addr;
          ret = inet_ntop(AF_INET6, sin6_addr, buf, sizeof(buf));
        }
        if (ret != NULL) {
          nic.ip.push_back(buf);
        }
      }
    }

    if (config_.method == config::ndis) {
      thread_ = std::thread(&capture::ndis, this);
    } else if (config_.method == config::raw) {
      thread_ = std::thread(&capture::raw, this);
    }
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

  void ndis() {
    static char kLoggerName[] = "tcpcap";
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
      status = ::StartTraceA(&session, kLoggerName, props);
      if (status == ERROR_ALREADY_EXISTS) {
        status =
            ::ControlTraceA(0, kLoggerName, props, EVENT_TRACE_CONTROL_STOP);
        assert(status == 0);

        status = ::StartTraceA(&session, kLoggerName, props);
        assert(status == 0);
      }
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to StartTrace().");
      }

      status = ::EnableTraceEx(&kNdisGuid, NULL, session, 1,
                               TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to EnableTraceEx2().");
      }

      // process packets
      static auto callback = [](PEVENT_RECORD ev) {
        assert(ev->UserContext != NULL);
        capture* self = static_cast<capture*>(ev->UserContext);
        self->process_packet_ndis(ev);
      };
      EVENT_TRACE_LOGFILEA logfile{};
      logfile.LoggerName = kLoggerName;
      logfile.ProcessTraceMode =
          PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
      logfile.Context = this;
      logfile.EventRecordCallback = callback;
      TRACEHANDLE tracehandle = ::OpenTraceA(&logfile);
      if (tracehandle == INVALID_PROCESSTRACE_HANDLE) {
        throw std::runtime_error("failed to OpenTrace().");
      }

      status = ::ProcessTrace(&tracehandle, 1, nullptr, nullptr);
      if (status != ERROR_SUCCESS) {
        throw std::runtime_error("failed to ProcessTrace().");
      }

      status = ::ControlTraceA(session, kLoggerName, props,
                               EVENT_TRACE_CONTROL_STOP);
    } catch (std::exception& ex) {
      error_cb(ex.what());
      if (session != NULL) {
        status = ::ControlTraceA(session, kLoggerName, props,
                                 EVENT_TRACE_CONTROL_STOP);
      }
    }
  }

  void raw() {
    struct WSAInitializer {
      WSAInitializer() {
        WSADATA wsa{};
        int ret = ::WSAStartup(MAKEWORD(2, 2), &wsa);
        if (ret != 0) {
          throw std::runtime_error("failed to WSAStartup().");
        }
      }
      ~WSAInitializer() { ::WSACleanup(); }
    } wsa;

    SOCKET s = INVALID_SOCKET;
    try {
      s = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
      if (s == INVALID_SOCKET) {
        throw std::runtime_error("failed to socket().");
      }

      std::string network;
      for (const auto& [index, nic] : nic_) {
        for (const auto& ip : nic.ip) {
          if (config_.network) {
            if (std::regex_match(ip, *config_.network)) {
              network = ip;
              break;
            }
          } else if (nic.mac[0] != 0x00) {
            // select first nic which has physical address
            network = ip;
            break;
          }
        }
      }

      if (network.empty()) {
        throw std::runtime_error("network not found.");
      }

      int ret;
      int port = 0;
      sockaddr_in server{};
      server.sin_family = AF_INET;
      server.sin_addr.s_addr = inet_addr(network.c_str());
      server.sin_port = htons(port);
      ret = ::bind(s, (sockaddr*)&server, sizeof(server));
      if (ret != 0) {
        throw std::runtime_error("failed to bind().");
      }

      unsigned long optval = 1;
      ret = ::ioctlsocket(s, SIO_RCVALL, &optval);
      if (ret != 0) {
        throw std::runtime_error("failed to ioctlsocket().");
      }

      std::vector<uint8_t> buf(65535);
      while (!exit_) {
        int len = ::recv(s, (char*)buf.data(), (int)buf.size(), 0);
        if (len <= 0) {
          throw std::runtime_error("failed to recv().");
        }
        process_packet(buf.data(), len);
      }
    } catch (std::exception& ex) {
      error_cb(std::format("tcpcap: exception {}", ex.what()));
    }

    if (s != INVALID_SOCKET) {
      ::closesocket(s);
    }
  }

  void process_packet_ndis(PEVENT_RECORD ev) {
    if (ev->EventHeader.ProviderId != kNdisGuid) {
      return;
    }

    const auto& ed = ev->EventHeader.EventDescriptor;
    if ((ed.Version << 16 | ed.Id) != 1001) {  // packet fragment
      return;
    }

    uint8_t* buf = (uint8_t*)ev->UserData;
    const uint32_t miniport_if = *(uint32_t*)(buf + 0);
    const uint32_t lower_if = *(uint32_t*)(buf + 4);
    const uint32_t fragment_size = *(uint32_t*)(buf + 8);
    uint8_t* fragment = buf + 12;

    if (!nic_.contains(miniport_if)) {
      assert(false && "miniport_if not found.");
      return;
    }

    if (config_.network) {
      bool matched =
          std::any_of(nic_[miniport_if].ip.begin(), nic_[miniport_if].ip.end(),
                      [&](const std::string& ip) {
                        return std::regex_match(ip, *config_.network);
                      });
      if (!matched) {
        return;
      }
    }

    size_t len = ev->UserDataLength;
    if (nic_[miniport_if].row.dwType == IF_TYPE_ETHERNET_CSMACD) {
      eth_header* eth = (eth_header*)fragment;
      if (htons(eth->type) != 0x0800) {  // ipv4
        return;
      }
      fragment += sizeof(eth_header);
      len -= sizeof(eth_header); 
    }

    process_packet(fragment, len);
  }

  void process_packet(uint8_t* buf, size_t len) {
    uint8_t* fragment = buf;
    const ip_header* ip = (ip_header*)fragment;
    const unsigned char ip_hdr_version = (ip->ver_ihl & 0xf0) >> 4;
    const unsigned char ip_hdr_size = (ip->ver_ihl & 0x0f) * 4;
    in_addr src_addr, dst_addr;
    src_addr.S_un.S_addr = ip->src_addr;
    dst_addr.S_un.S_addr = ip->dst_addr;
    std::string src_ip = inet_ntoa(src_addr);
    std::string dst_ip = inet_ntoa(dst_addr);

    if (ip->protocol != 0x06) {  // tcp
      return;
    }
    fragment += ip_hdr_size;

    const tcp_header* tcp = (tcp_header*)fragment;
    std::string src_port = std::to_string(htons(tcp->src_port));
    std::string dst_port = std::to_string(htons(tcp->dst_port));
    const uint8_t tcp_hdr_size = (tcp->data_offset >> 4) * 4;
    fragment += tcp_hdr_size;

    const uint8_t* payload = fragment;
    size_t payload_length = len - (fragment - buf);

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

    bool deny = std::any_of(
        config_.rules.begin(), config_.rules.end(), [&](const auto& r) {
          if (r.type == rule::deny) {
            std::string source = get_source(r);
            if (r.pattern && std::regex_match(source, *r.pattern)) {
              return true;
            }
          }
          return false;
        });
    bool allow =
        config_.rules.empty() ||
        std::any_of(
            config_.rules.begin(), config_.rules.end(), [&](const auto& r) {
              if (r.type == rule::allow) {
                std::string source = get_source(r);
                if (r.pattern && std::regex_match(source, *r.pattern)) {
                  return true;
                }
              }
              return false;
            });
    if (deny || !allow) {
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

  struct nic {
    MIB_IFROW row;
    std::vector<std::string> ip;
    uint8_t mac[6];
  };
  std::unordered_map<uint32_t, nic> nic_;
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
