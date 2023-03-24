# pktcap
tcp packet capture using ETW and NDIS provider

usage:
```
pktcap::config config;

pktcap::rule rule;
rule.type = pktcap::rule::allow;
rule.dir = pktcap::rule::src;
rule.source = pktcap::rule::ip;
rule.pattern = "18.*";  // Regex
config.rules.push_back(rule);

rule.pattern = "6000";
config.rules.push_back(rule);

config.packet_cb = [=](const uint8_t* buf, size_t len,
                      const std::string& src_ip, int src_port,
                      const std::string& dst_ip, int dst_port) {
  printf("%s:%d -> %s:%d len:%u\n", src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, len);
};
config.error_cb = [=](const std::string& msg) {
  printf("tcpcap error: %s\n", msg.c_str());
};
int id = pktcap::start_capture(config);  // runs on a background thread
...
pktcap::stop_capture(id);
```
