#pragma once

#include "dnsRecord.hpp"

#include <string>
#include <arpa/inet.h>
#include <array>
#include <sstream>

namespace ipxp
{
   
constexpr static 
std::string processA(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (data.size() < sizeof(uint32_t)) {
		return {};
	}

	const uint32_t address = *reinterpret_cast<const uint32_t*>(
        data.data());
	std::array<char, INET_ADDRSTRLEN> addressStr;
	inet_ntop(AF_INET, &address, addressStr.data(), INET_ADDRSTRLEN);
	oss << addressStr.data();

    return oss.str();
}

constexpr static std::string processAAAA(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
    if (data.size() < INET6_ADDRSTRLEN) {
        return {};
    }

	std::array<char, INET6_ADDRSTRLEN> address;
	inet_ntop(AF_INET6, data.data(), address.data(), INET6_ADDRSTRLEN);
	oss << address.data();

    return oss.str();
}

constexpr static 
std::string processRawDataName(
    const std::byte* dnsBegin,
	std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (const std::optional<DNSName> name = DNSName::createFrom(
        data, dnsBegin);
		name.has_value()) {
		oss << name->toString();
	}

    return oss.str();
}

struct DNSSOARecord {
	uint32_t serialNumber;
	uint32_t refreshInterval;
	uint32_t retryInterval;
	uint32_t expireLimit;
	uint32_t minimumTTL;
};

static std::string processSOA(
    const std::byte* dnsBegin,
	std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	const std::optional<DNSName> name = DNSName::createFrom(
        data, dnsBegin);
	if (!name.has_value()) {
		return {};
	}
	const std::optional<DNSName> email
		= DNSName::createFrom(data.subspan(name->length()), dnsBegin);
	if (!email.has_value() || 
        name->length() + email->length() + sizeof(DNSSOARecord) > data.size()) {
		return {};
	}
	oss << name->toString() << " " << email->toString();

	const auto soa = reinterpret_cast<const DNSSOARecord*>(
		data.data() + name->length() + email->length());
	oss << " " << ntohl(soa->serialNumber) << " " << ntohl(soa->refreshInterval) << " "
		<< ntohl(soa->retryInterval) << " " << ntohl(soa->expireLimit) << " "
		<< ntohl(soa->minimumTTL);

    return oss.str();
}

constexpr static 
std::string processSRV(
    const std::byte* dnsBegin,
	std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (3 * sizeof(uint16_t) > data.size()) {
		return {};
	}

	const uint16_t priority = ntohs(*reinterpret_cast<const uint16_t*>(data.data()));
	const uint16_t weight
		= ntohs(*reinterpret_cast<const uint16_t*>(data.data() + sizeof(priority)));
	const uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(
		data.data() + sizeof(priority) + sizeof(weight)));
	const std::optional<DNSName> targetName = DNSName::createFrom(
		data.subspan(sizeof(priority) + sizeof(weight) + sizeof(port)), dnsBegin);
	if (!targetName.has_value()) {
		return;
	}

	oss << priority << " " << weight << " " << port << " " << targetName->toString();
	
    return oss.str();
}

constexpr static 
std::string processMX(
    const std::byte* dnsBegin,
	std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (data.size() < sizeof(uint16_t)) {
		return {};
	}

	const uint16_t preference = ntohs(*reinterpret_cast<const uint16_t*>(data.data()));
	const std::optional<DNSName> exchangeName
		= DNSName::createFrom(data.subspan(sizeof(preference)), dnsBegin);
	if (!exchangeName.has_value()) {
		return {};
	}

	oss << preference << " " << exchangeName->toString();
	return oss.str();
};

constexpr static 
std::string processMINFO(std::span<const std::byte> data) noexcept
{
	std::ostringstream oss;

	const std::optional<DNSName> rMailBox = DNSName::createFrom(data, dnsBegin);
	if (!rMailBox.has_value()) {
		return {};
	}

	const std::optional<DNSName> eMailBox
		= DNSName::createFrom(data.subspan(rMailBox->length()), dnsBegin);
	if (!eMailBox.has_value()) {
		return {};
	}

	oss << rMailBox->toString() << " " << eMailBox->toString();
	return oss.str();
};

constexpr static 
std::string processHINFO(
	std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	const std::optional<DNSName> cpu = DNSName::createFrom(data, dnsBegin);
	if (!cpu.has_value()) {
		return {};
	}

	const std::optional<DNSName> operatingSystem
		= DNSName::createFrom(data.subspan(cpu->length()), dnsBegin);
	if (!operatingSystem.has_value()) {
		return;
	}

	oss << cpu->toString() << " " << operatingSystem->toString();
    return oss.str();
};

constexpr static 
std::string processISDN(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	const std::optional<DNSName> isdnAddress = DNSName::createFrom(data, dnsBegin);
	if (!isdnAddress.has_value()) {
		return {};
	}

	const std::optional<DNSName> subaddress
		= DNSName::createFrom(data.subspan(isdnAddress->length()), dnsBegin);
	if (!subaddress.has_value()) {
		return;
	}

	oss << isdnAddress->toString() << " " << subaddress->toString();
    return oss.str();
};

constexpr static 
std::string processDS(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (data.size() < sizeof(uint16_t) + 2 * sizeof(uint8_t)) {
		return {};
	}
	const uint16_t keytag = ntohs(*reinterpret_cast<const uint16_t*>(data.data()));
	const uint8_t algorithm
		= *reinterpret_cast<const uint8_t*>(data.data() + sizeof(keytag));
	const uint8_t digestType = *reinterpret_cast<const uint8_t*>(
		data.data() + sizeof(keytag) + sizeof(algorithm));

	oss << keytag << " " << static_cast<uint16_t>(algorithm) << " "
		<< static_cast<uint16_t>(digestType) << " <key>";
}

constexpr static 
std::string processTXT(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	const std::optional<DNSName> txt = DNSName::createFrom(data, dnsBegin);
	if (!txt.has_value() || txt->length() == 0) {
		return {};
	}

    std::string res = txt->toString();
    const std::size_t firstPoint = res.find('.');
    if (firstPoint != std::string::npos) {
        res[firstPoint] = ' ';
    }

	oss << res;
    return oss.str();
}

struct DNSRRSIG {
	uint16_t typeCovered;
	uint8_t algorithm;
	uint8_t labels;
	uint32_t originalTTL;
	uint32_t expiration;
	uint32_t inception;
	uint16_t keyTag;
};

constexpr static 
std::string processRRSIG(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (data.size() < sizeof(DNSRRSIG)) {
		return {};
	}
	const auto* rrsig = reinterpret_cast<const DNSRRSIG*>(data.data());
	oss << ntohs(rrsig->typeCovered) << " " << static_cast<uint16_t>(rrsig->algorithm) << " "
		<< static_cast<uint16_t>(rrsig->labels) << " " << ntohl(rrsig->originalTTL) << " "
		<< ntohl(rrsig->expiration) << " " << ntohl(rrsig->inception) << " "
		<< ntohs(rrsig->keyTag);
	return oss.str();
}

struct DNSKey {
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
};

static constexpr 
std::string processDNSKEY(std::span<const std::byte> data) noexcept
{
    std::ostringstream oss;
	if (data.size() < sizeof(DNSKey)) {
		return {};
    }

	const auto* dnsKey = reinterpret_cast<const DNSKey*>(data.data());
	oss << ntohs(dnsKey->flags) << " " << static_cast<uint16_t>(dnsKey->protocol) << " "
		<< static_cast<uint16_t>(dnsKey->algorithm) << " <key>";
	return oss.str();
}


std::string DNSRecord::toString(const std::byte* dnsBegin) const noexcept
{
	switch (type) {
	case DNSQueryType::A:
		return processA(this->data);
	case DNSQueryType::AAAA:
		return processAAAA(this->data);
	case DNSQueryType::NS: [[fallthrough]];
	case DNSQueryType::CNAME: [[fallthrough]];
	case DNSQueryType::PTR:
		return processRawDataName(dnsBegin, this->data);
	case DNSQueryType::SOA:
		return processSOA(dnsBegin, this->data);
	case DNSQueryType::MX:
		return processMX(dnsBegin, this->data);
	case DNSQueryType::TXT:
		return processTXT(this->data);
	case DNSQueryType::ISDN:
		return processISDN(this->data);
	case DNSQueryType::HINFO:
		return processHINFO(this->data);
	case DNSQueryType::MINFO:
		return processMINFO(this->data);
	case DNSQueryType::SRV:
		return processSRV(dnsBegin, this->data);
	case DNSQueryType::RRSIG:
		return processRRSIG(this->data);
	case DNSQueryType::DNSKEY:
		return processDNSKEY(this->data);
	case DNSQueryType::DS:
		return processDS(this->data);
	default:
		return "";
	}
}

    
} // namespace ipxp
