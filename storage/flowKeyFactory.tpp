#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <variant>
#include <optional>
#include "flowKey.tpp"

namespace ipxp {

class FlowKeyFactory {
public:

   template<typename Int>
   static std::optional<std::variant<FlowKeyv4, FlowKeyv6>>
    create_direct_key(const Int* src_ip, const Int* dst_ip,
                      uint16_t src_port, uint16_t dst_port, uint8_t proto, IP ip_version) noexcept
   {
      if (ip_version == IP::v4) {
         return FlowKeyFactory::create_direct_key<IP::v4>(src_ip, dst_ip, src_port, dst_port, proto);
      }
      if (ip_version == IP::v6) {
         return FlowKeyFactory::create_direct_key<IP::v6>(src_ip, dst_ip, src_port, dst_port, proto);
      }
      return std::nullopt;
   }

   template<typename Int>
   static std::optional<std::variant<FlowKeyv4, FlowKeyv6>>
   create_reversed_key(const Int* src_ip, const Int* dst_ip,
                       uint16_t src_port, uint16_t dst_port, uint8_t proto, IP ip_version) noexcept
   {
      if (ip_version == IP::v4) {
         return FlowKeyFactory::create_reversed_key<IP::v4>(src_ip, dst_ip, src_port, dst_port, proto);
      }
      if (ip_version == IP::v6) {
         return FlowKeyFactory::create_reversed_key<IP::v6>(src_ip, dst_ip, src_port, dst_port, proto);
      }
      return std::nullopt;
   }

   template<IP Version, typename Int>
   static FlowKey<Version>
   create_direct_key(const Int* src_ip, const Int* dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) noexcept
   {
      FlowKey<Version> res;
      std::copy(reinterpret_cast<const uint8_t*>(src_ip),
                reinterpret_cast<const uint8_t*>(src_ip) + FlowKey<Version>::AddressSize, res.src_ip.begin());
      std::copy(reinterpret_cast<const uint8_t*>(dst_ip),
                reinterpret_cast<const uint8_t*>(dst_ip) + FlowKey<Version>::AddressSize, res.dst_ip.begin());
      res.src_port = src_port;
      res.dst_port = dst_port;
      res.proto = proto;
      res.ip_version = Version;
      return res;
   }

   template<IP Version, typename Int>
   static FlowKey<Version>
   create_reversed_key(const Int* src_ip, const Int* dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) noexcept
   {
      FlowKey<Version> res;
      std::copy(reinterpret_cast<const uint8_t*>(src_ip),
                reinterpret_cast<const uint8_t*>(src_ip) + FlowKey<Version>::AddressSize, res.dst_ip.begin());
      std::copy(reinterpret_cast<const uint8_t*>(dst_ip),
                reinterpret_cast<const uint8_t*>(dst_ip) + FlowKey<Version>::AddressSize, res.src_ip.begin());
      res.src_port = dst_port;
      res.dst_port = src_port;
      res.proto = proto;
      res.ip_version = Version;
      return res;
   }
};

} // ipxp