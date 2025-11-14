/**
 * @file quicInitialHeaderView.cpp
 * @brief Definition of QUICInitialHeaderView for parsing QUIC Initial packet headers.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include "quicInitialHeaderView.hpp"

#include "opensslContext.hpp"
#include "quicVariableInt.hpp"

#include <algorithm>
#include <bit>
#include <iostream>
#include <ranges>
#include <string_view>

#include <arpa/inet.h>
#include <boost/container/static_vector.hpp>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <utils/spanUtils.hpp>

namespace ipxp::process::quic {

using ExpandedLabel
	= boost::container::static_vector<std::byte, QUICInitialHeaderView::MAX_EXPANDED_LABEL_LENGTH>;

template<uint16_t DesiredLength>
constexpr static ExpandedLabel expandLabel(std::string_view prefix, std::string_view label) noexcept
{
	/* HKDF-Expand-Label(Secret, Label, Context, Length) =
	 *      HKDF-Expand(Secret, HkdfLabel, Length)
	 *
	 * Where HkdfLabel is specified as:
	 *
	 * struct {
	 *     uint16 length = Length;
	 *     opaque label<7..255> = "tls13 " + Label;
	 *     opaque context<0..255> = Context;
	 * } HkdfLabel;
	 *
	 *
	 * https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
	 * "... the actual length precedes the vector's contents in the byte stream ... "
	 * */

	ExpandedLabel res;

	const uint16_t convertedDesiredLength = htons(DesiredLength);
	res.push_back(static_cast<std::byte>(convertedDesiredLength & 0xFF));
	res.push_back(static_cast<std::byte>(convertedDesiredLength >> 8));
	res.push_back(static_cast<std::byte>(prefix.size() + label.size()));

	res.insert(
		res.end(),
		reinterpret_cast<const std::byte*>(prefix.data()),
		reinterpret_cast<const std::byte*>(prefix.data() + prefix.size()));

	res.insert(
		res.end(),
		reinterpret_cast<const std::byte*>(label.data()),
		reinterpret_cast<const std::byte*>(label.data() + label.size()));

	// Context length is always zero
	res.push_back(std::byte {0});

	return res;
}

template<std::size_t BufferSize>
constexpr static std::optional<std::array<std::byte, BufferSize>>
deriveFromSecret(std::span<const std::byte> secret, std::span<const std::byte> expandedLabel)
{
	auto keyContext = createKeyContext();

	auto derived = std::make_optional<std::array<std::byte, BufferSize>>();
	std::size_t derivedLength = BufferSize;

	// pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!keyContext ||
		// context initialization failed
		!EVP_PKEY_derive_init(keyContext.get()) ||
		// mode initialization failed
		!EVP_PKEY_CTX_hkdf_mode(keyContext.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) ||
		// message digest initialization failed
		!EVP_PKEY_CTX_set_hkdf_md(keyContext.get(), EVP_sha256()) ||
		// info initialization failed
		!EVP_PKEY_CTX_add1_hkdf_info(
			keyContext.get(),
			reinterpret_cast<const uint8_t*>(expandedLabel.data()),
			expandedLabel.size())
		||
		// key initialization failed
		!EVP_PKEY_CTX_set1_hkdf_key(
			keyContext.get(),
			reinterpret_cast<const uint8_t*>(secret.data()),
			QUICInitialHeaderView::SHA2_256_LENGTH)
		||
		// HKDF-Expand derivation failed
		!EVP_PKEY_derive(
			keyContext.get(),
			reinterpret_cast<uint8_t*>(derived->data()),
			&derivedLength)) {
		return std::nullopt;
	}
	return derived;
}

static std::optional<QUICInitialSecrets>
deriveSecrets(std::span<const std::byte> secret, const bool isSecondGeneration) noexcept
{
	auto res = std::make_optional<QUICInitialSecrets>();

	const std::string_view keyLabel = isSecondGeneration ? "quicv2 key" : "quic key";
	const std::string_view initialVectorLabel = isSecondGeneration ? "quicv2 iv" : "quic iv";
	const std::string_view headerProtectionLabel = isSecondGeneration ? "quicv2 hp" : "quic hp";

	// use HKDF-Expand to derive other secrets
	const ExpandedLabel expandedKey
		= expandLabel<QUICInitialSecrets::AES_128_KEY_LENGTH>("tls13 ", keyLabel);
	const std::optional<std::array<std::byte, QUICInitialSecrets::AES_128_KEY_LENGTH>> keyDerived
		= deriveFromSecret<QUICInitialSecrets::AES_128_KEY_LENGTH>(
			secret,
			toSpan<const std::byte>(expandedKey));
	if (!keyDerived) {
		return std::nullopt;
	}

	res->key = *keyDerived;

	const ExpandedLabel expandedInitialVector
		= expandLabel<QUICInitialSecrets::TLS13_AEAD_NONCE_LENGTH>("tls13 ", initialVectorLabel);
	const std::optional<std::array<std::byte, QUICInitialSecrets::TLS13_AEAD_NONCE_LENGTH>>
		initialVectorDerived = deriveFromSecret<QUICInitialSecrets::TLS13_AEAD_NONCE_LENGTH>(
			secret,
			toSpan<const std::byte>(expandedInitialVector));
	if (!initialVectorDerived) {
		return std::nullopt;
	}

	res->initialVector = *initialVectorDerived;

	const ExpandedLabel expandedHeaderProtection
		= expandLabel<QUICInitialSecrets::AES_128_KEY_LENGTH>("tls13 ", headerProtectionLabel);
	const std::optional<std::array<std::byte, QUICInitialSecrets::AES_128_KEY_LENGTH>>
		headerProtectionDerived = deriveFromSecret<QUICInitialSecrets::AES_128_KEY_LENGTH>(
			secret,
			toSpan<const std::byte>(expandedHeaderProtection));
	if (!headerProtectionDerived) {
		return std::nullopt;
	}

	res->headerProtection = *headerProtectionDerived;

	return res;
}

std::optional<QUICInitialSecrets> createInitialSecrets(
	std::span<const uint8_t> destConnectionId,
	std::span<const std::byte> salt,
	const bool isSecondGeneration) noexcept
{
	// Set DCID if not set by previous packet
	/*if (initial_dcid_len == 0) {
		initial_dcid_len = dcid_len;
		initial_dcid = (uint8_t*) dcid;
	}*/

	std::array<std::byte, QUICInitialHeaderView::SHA2_256_LENGTH> extractedSecret;
	std::size_t extractedSecretLength = QUICInitialHeaderView::SHA2_256_LENGTH;

	std::array<std::byte, QUICInitialHeaderView::SHA2_256_LENGTH> expandedSecret;
	size_t expandedSecretLength = QUICInitialHeaderView::SHA2_256_LENGTH;

	// HKDF-Extract
	// std::unique_ptr<EVP_PKEY_CTX> publicKeyContext
	auto publicKeyContext = createKeyContext();

	const ExpandedLabel expandedLabel
		= expandLabel<QUICInitialHeaderView::SHA2_256_LENGTH>("tls13 ", "client in");

	/// context initialization
	if (!EVP_PKEY_derive_init(publicKeyContext.get()) ||
		// mode initialization
		!EVP_PKEY_CTX_hkdf_mode(publicKeyContext.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) ||
		// message digest initialization
		!EVP_PKEY_CTX_set_hkdf_md(publicKeyContext.get(), EVP_sha256()) ||
		// salt initialization
		!EVP_PKEY_CTX_set1_hkdf_salt(
			publicKeyContext.get(),
			reinterpret_cast<const uint8_t*>(salt.data()),
			salt.size())
		||
		// key initialization
		!EVP_PKEY_CTX_set1_hkdf_key(
			publicKeyContext.get(),
			destConnectionId.data(),
			destConnectionId.size())
		||
		// HKDF-Extract derivation
		!EVP_PKEY_derive(
			publicKeyContext.get(),
			reinterpret_cast<uint8_t*>(extractedSecret.data()),
			&extractedSecretLength)
		||
		// Expand context initialization
		!EVP_PKEY_derive_init(publicKeyContext.get()) ||
		// Expand mode initialization
		!EVP_PKEY_CTX_hkdf_mode(publicKeyContext.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) ||
		// Expand message digest initialization
		!EVP_PKEY_CTX_set_hkdf_md(publicKeyContext.get(), EVP_sha256()) ||
		// Expand info initialization
		!EVP_PKEY_CTX_add1_hkdf_info(
			publicKeyContext.get(),
			reinterpret_cast<const uint8_t*>(expandedLabel.data()),
			expandedLabel.size())
		||
		// Expand key initialization
		!EVP_PKEY_CTX_set1_hkdf_key(
			publicKeyContext.get(),
			reinterpret_cast<const uint8_t*>(extractedSecret.data()),
			extractedSecretLength)
		||
		// HKDF-Expand derivation
		!EVP_PKEY_derive(
			publicKeyContext.get(),
			reinterpret_cast<uint8_t*>(expandedSecret.data()),
			&expandedSecretLength)) {
		return std::nullopt;
	}

	return deriveSecrets(toSpan<const std::byte>(expandedSecret), isSecondGeneration);
}

static std::optional<std::span<const std::byte>>
encryptSample(const QUICInitialSecrets& initialSecrets, std::span<const std::byte> sample)
{
	static std::array<std::byte, QUICInitialHeaderView::SAMPLE_LENGTH> plaintext;

	auto cipherContext = createCipherContext();

	// context creation failed
	if (!cipherContext ||
		// context initialization failed
		!EVP_EncryptInit_ex(
			cipherContext.get(),
			EVP_aes_128_ecb(),
			nullptr,
			reinterpret_cast<const uint8_t*>(initialSecrets.headerProtection.data()),
			nullptr)) {
		return std::nullopt;
	}

	// we need to disable padding so we can use EncryptFinal
	EVP_CIPHER_CTX_set_padding(cipherContext.get(), 0);

	int updateLength = 0;
	int finalLength = 0;
	// decrypting header
	if (!EVP_EncryptUpdate(
			cipherContext.get(),
			reinterpret_cast<uint8_t*>(plaintext.data()),
			&updateLength,
			reinterpret_cast<const uint8_t*>(sample.data()),
			sample.size())
		||
		// final header decryption
		!EVP_EncryptFinal_ex(
			cipherContext.get(),
			reinterpret_cast<uint8_t*>(plaintext.data() + updateLength),
			&finalLength)) {
		return std::nullopt;
	}

	if (updateLength + finalLength > plaintext.size()) {
		return std::nullopt;
	}

	return toSpan<const std::byte>(plaintext.data(), updateLength + finalLength);
}

static std::optional<QUICInitialHeaderView::DeobfuscatedHeader> decryptInitialHeader(
	std::span<const std::byte> payload,
	QUICInitialSecrets& initialSecrets,
	std::span<const std::byte> sample,
	// const std::byte formHeader,
	const std::size_t primaryHeaderLength,
	const std::byte* encryptedPacketNumber) noexcept
{
	// uint8_t plaintext[SAMPLE_LENGTH];
	std::array<std::byte, 5> mask;
	auto deobfuscatedHeader = std::make_optional<QUICInitialHeaderView::DeobfuscatedHeader>();
	// std::array<std::byte, 4> full_pkn;
	// std::byte first_byte = 0;
	// uint32_t packet_number = 0;

	// https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-applicati

	/*
	 * mask = header_protection(hp_key, sample)
	 *
	 * pn_length = (packet[0] & 0x03) + 1
	 *
	 * if (packet[0] & 0x80) == 0x80:
	 # Long header: 4 bits masked
	 #    packet[0] ^= mask[0] & 0x0f
	 # else:
	 # Short header: 5 bits masked
	 #    packet[0] ^= mask[0] & 0x1f
	 */

	// Encrypt sample with AES-ECB. Encrypted sample is used in XOR with packet header
	std::optional<std::span<const std::byte>> plaintext = encryptSample(initialSecrets, sample);
	if (!plaintext.has_value()) {
		return std::nullopt;
	}

	std::copy(plaintext->data(), plaintext->data() + mask.size(), mask.begin());

	// std::span<const std::byte> primaryHeaderPayload
	//	= payload.subspan(-primaryHeaderLength, payload.size() + primaryHeaderLength);
	const std::byte deobfuscatedFormHeader = payload[0] ^ (mask[0] & std::byte {0x0f});
	const uint8_t packetNumberLength = (static_cast<uint8_t>(deobfuscatedFormHeader) & 0x03) + 1;

	if (encryptedPacketNumber + packetNumberLength - payload.data() > payload.size()) {
		return std::nullopt;
	}
	if (encryptedPacketNumber + packetNumberLength - payload.data()
		> deobfuscatedHeader->capacity()) {
		return std::nullopt;
	}

	deobfuscatedHeader->insert(
		deobfuscatedHeader->end(),
		payload.data(),
		encryptedPacketNumber + packetNumberLength);

	// deobfuscatedHeader->push_back(deobfuscatedFormHeader);
	(*deobfuscatedHeader)[0] = deobfuscatedFormHeader;

	/*std::ranges::copy_n(
		encryptedPacketNumber,
		packetNumberLength,
		std::back_inserter(*deobfuscatedHeader));*/
	// after de-obfuscating pkn, we know exactly pkn length so we can correctly adjust start of
	// payload
	/*payload = payload + pkn_len;
	payload_len = payload_len - pkn_len;
	if (payload_len > CURRENT_BUFFER_SIZE) {
		DEBUG_MSG("Payload length underflow\n");
		return false;
	}
	header_len = payload - payload_pointer;
	if (header_len > MAX_HEADER_LEN) {
		DEBUG_MSG("Header length too long\n");
		return false;
	}

	memcpy(tmp_header_mem, payload_pointer, header_len);
	header = tmp_header_mem;

	header[0] = first_byte;

	memcpy(&full_pkn, pkn, pkn_len);*/

	std::array<std::byte, 4> packetNumberBytes;

	std::for_each_n(
		encryptedPacketNumber,
		packetNumberLength,
		[&, index = 0](const std::byte obfuscatedByte) mutable {
			packetNumberBytes[index + 4 - packetNumberLength] = obfuscatedByte ^ mask[index + 1];
			index++;
		});

	const uint32_t packetNumber = ntohl(std::bit_cast<uint32_t>(packetNumberBytes));

	// adjust nonce for payload decryption
	// https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
	//  The exclusive OR of the padded packet number and the IV forms the AEAD nonce

	uint64_t* initialVectorEnd = reinterpret_cast<uint64_t*>(
		initialSecrets.initialVector.data() + initialSecrets.initialVector.size()
		- sizeof(uint64_t));

	*initialVectorEnd = htobe64(be64toh(*initialVectorEnd) ^ packetNumber);

	std::copy_n(
		packetNumberBytes.rbegin(),
		packetNumberLength,
		deobfuscatedHeader->data() + deobfuscatedHeader->size() - packetNumberLength);

	return deobfuscatedHeader;
}

static std::optional<QUICInitialHeaderView::DecryptedPayload> decryptPayload(
	std::span<const std::byte> encryptedPayload,
	QUICInitialSecrets& initialSecrets,
	const QUICInitialHeaderView::DeobfuscatedHeader& deobfuscatedHeader) noexcept
{
	std::array<std::byte, 16> authTag {};

	if (encryptedPayload.size() <= authTag.size()) {
		return std::nullopt;
	}
	/* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */
	if (encryptedPayload.size() > QUICInitialHeaderView::ReassembledFrame::capacity()) {
		return std::nullopt;
	}

	auto decryptedPayload = std::make_optional<QUICInitialHeaderView::DecryptedPayload>();
	decryptedPayload->resize(decryptedPayload->capacity());

	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
	// "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger
	// than their input." adjust length because last 16 bytes are authentication tag

	std::copy_n(encryptedPayload.end() - authTag.size(), authTag.size(), authTag.begin());
	encryptedPayload = encryptedPayload.subspan(0, encryptedPayload.size() - authTag.size());

	auto cipherContext = createCipherContext();

	int initUpdateLength;
	int payloadUpdateLength;
	int finalLength;
	if (!cipherContext ||
		// context initialization
		!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) ||
		// setting NONCE length
		!EVP_CIPHER_CTX_ctrl(
			cipherContext.get(),
			EVP_CTRL_AEAD_SET_IVLEN,
			QUICInitialSecrets::TLS13_AEAD_NONCE_LENGTH,
			nullptr)
		||
		// setting KEY and NONCE
		!EVP_DecryptInit_ex(
			cipherContext.get(),
			nullptr,
			nullptr,
			reinterpret_cast<uint8_t*>(initialSecrets.key.data()),
			reinterpret_cast<uint8_t*>(initialSecrets.initialVector.data()))
		||
		// initializing authenticated data
		!EVP_DecryptUpdate(
			cipherContext.get(),
			nullptr,
			&initUpdateLength,
			reinterpret_cast<const uint8_t*>(deobfuscatedHeader.data()),
			deobfuscatedHeader.size())
		||
		// decrypting payload
		!EVP_DecryptUpdate(
			cipherContext.get(),
			reinterpret_cast<uint8_t*>(decryptedPayload->data()),
			&payloadUpdateLength,
			reinterpret_cast<const uint8_t*>(encryptedPayload.data()),
			encryptedPayload.size())
		||
		// TAG check
		!EVP_CIPHER_CTX_ctrl(
			cipherContext.get(),
			EVP_CTRL_AEAD_SET_TAG,
			authTag.size(),
			authTag.data())
		||
		// final payload decryption
		!EVP_DecryptFinal_ex(
			cipherContext.get(),
			reinterpret_cast<uint8_t*>(decryptedPayload->data() + payloadUpdateLength),
			&finalLength)) {
		return std::nullopt;
	}

	decryptedPayload->resize(initUpdateLength + payloadUpdateLength + finalLength);
	return decryptedPayload;
}

constexpr static std::optional<std::span<const std::byte>>
getCryptoData(std::span<const std::byte> payload) noexcept
{
	const std::optional<VariableLengthInt> frameOffset = readQUICVariableLengthInt(payload);
	if (!frameOffset.has_value()) {
		return std::nullopt;
	}

	const std::size_t lengthOffset = frameOffset->length;
	const std::optional<VariableLengthInt> length
		= readQUICVariableLengthInt(payload.subspan(lengthOffset));
	if (!length.has_value()) {
		return std::nullopt;
	}

	return std::span<const std::byte>(
		payload.data() + lengthOffset + length->length,
		length->value);
}

constexpr static std::optional<std::size_t>
skipAck1Frame(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	const std::optional<VariableLengthInt> lastAcknowledged = readQUICVariableLengthInt(payload);
	if (!lastAcknowledged.has_value()) {
		return std::nullopt;
	}

	const std::size_t delayOffset = lastAcknowledged->length;
	const std::optional<VariableLengthInt> delay
		= readQUICVariableLengthInt(payload.subspan(delayOffset));
	if (!delay.has_value()) {
		return std::nullopt;
	}

	const std::size_t ackRangeCountOffset = delayOffset + delay->length;
	const std::optional<VariableLengthInt> ackRangeCount
		= readQUICVariableLengthInt(payload.subspan(ackRangeCountOffset));
	if (!ackRangeCount.has_value()) {
		return std::nullopt;
	}

	const std::size_t firstAckRangeOffset = ackRangeCountOffset + ackRangeCount->length;
	const std::optional<VariableLengthInt> firstAckRange
		= readQUICVariableLengthInt(payload.subspan(firstAckRangeOffset));
	if (!firstAckRange.has_value()) {
		return std::nullopt;
	}

	std::size_t rangeOffset = firstAckRangeOffset + firstAckRange->length;
	for (uint64_t rangeIndex = 0; rangeIndex < ackRangeCount->value; rangeIndex++) {
		const std::optional<VariableLengthInt> gap
			= readQUICVariableLengthInt(payload.subspan(rangeOffset));
		if (!gap.has_value()) {
			return std::nullopt;
		}

		const std::optional<VariableLengthInt> rangeLength
			= readQUICVariableLengthInt(payload.subspan(rangeOffset + gap->length));
		if (!rangeLength.has_value()) {
			return std::nullopt;
		}

		rangeOffset += gap->length + rangeLength->length;
	}

	return rangeOffset;
}

constexpr static std::optional<std::size_t>
skipAck2Frame(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	const std::optional<std::size_t> ack1FrameLength = skipAck1Frame(payload);
	if (!ack1FrameLength.has_value()) {
		return std::nullopt;
	}

	const std::size_t ect0Offset = *ack1FrameLength;
	const std::optional<VariableLengthInt> ect0PacketCount
		= readQUICVariableLengthInt(payload.subspan(ect0Offset));
	if (!ect0PacketCount.has_value()) {
		return std::nullopt;
	}

	const std::size_t ect1Offset = ect0Offset + ect0PacketCount->length;
	const std::optional<VariableLengthInt> ect1PacketCount
		= readQUICVariableLengthInt(payload.subspan(ect1Offset));
	if (!ect1PacketCount.has_value()) {
		return std::nullopt;
	}

	const std::size_t congestionExperiencedOffset = ect1Offset + ect1PacketCount->length;
	const std::optional<VariableLengthInt> congestionExperiencedCount
		= readQUICVariableLengthInt(payload.subspan(congestionExperiencedOffset));
	if (!congestionExperiencedCount.has_value()) {
		return std::nullopt;
	}

	return congestionExperiencedOffset + congestionExperiencedCount->length;
}

constexpr static std::optional<std::size_t>
skipConnectionClose1Frame(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	const std::optional<VariableLengthInt> errorCode = readQUICVariableLengthInt(payload);
	if (!errorCode.has_value()) {
		return std::nullopt;
	}

	const std::size_t frameTypeOffset = errorCode->length;
	const std::optional<VariableLengthInt> frameType
		= readQUICVariableLengthInt(payload.subspan(frameTypeOffset));
	if (!frameType.has_value()) {
		return std::nullopt;
	}

	const std::size_t reasonPhraseLengthOffset = frameTypeOffset + frameType->length;
	const std::optional<VariableLengthInt> reasonPhraseLength
		= readQUICVariableLengthInt(payload.subspan(reasonPhraseLengthOffset));
	if (!reasonPhraseLength.has_value()) {
		return std::nullopt;
	}

	return reasonPhraseLengthOffset + reasonPhraseLength->length + reasonPhraseLength->value;
}

constexpr static std::optional<std::size_t>
skipConnectionClose2Frame(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	const std::optional<VariableLengthInt> errorCode = readQUICVariableLengthInt(payload);
	if (!errorCode.has_value()) {
		return std::nullopt;
	}

	const std::size_t reasonPhraseLengthOffset = errorCode->length;
	const std::optional<VariableLengthInt> reasonPhraseLength
		= readQUICVariableLengthInt(payload.subspan(reasonPhraseLengthOffset));
	if (!reasonPhraseLength.has_value()) {
		return std::nullopt;
	}

	return reasonPhraseLengthOffset + reasonPhraseLength->length + reasonPhraseLength->value;
}

constexpr static std::optional<QUICInitialHeaderView::ReassembledFrame>
reassembleCryptoFrames(std::span<const std::byte> decryptedPayload) noexcept
{
	auto reassembledFrame = std::make_optional<QUICInitialHeaderView::ReassembledFrame>();

	while (!decryptedPayload.empty()) {
		// https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
		// only those frames can occure in initial packets
		std::optional<std::size_t> frameLength;
		const QUICInitialHeaderView::FrameType frameType
			= static_cast<QUICInitialHeaderView::FrameType>(decryptedPayload[0]);
		decryptedPayload = decryptedPayload.subspan(sizeof(QUICInitialHeaderView::FrameType));

		switch (frameType) {
		case QUICInitialHeaderView::FrameType::CRYPTO: {
			std::optional<std::span<const std::byte>> cryptoData = getCryptoData(decryptedPayload);
			if (!cryptoData.has_value()
				|| reassembledFrame->size() + cryptoData->size() > reassembledFrame->capacity()) {
				return std::nullopt;
			}
			const std::size_t sizeToCopy = std::min(
				cryptoData->size(),
				reassembledFrame->capacity() - reassembledFrame->size());
			reassembledFrame->insert(
				reassembledFrame->end(),
				cryptoData->begin(),
				cryptoData->begin() + sizeToCopy);

			frameLength = cryptoData->data() - decryptedPayload.data() + cryptoData->size();
			break;
		}
		case QUICInitialHeaderView::FrameType::ACK1: {
			frameLength = skipAck1Frame(decryptedPayload);
			break;
		}
		case QUICInitialHeaderView::FrameType::ACK2: {
			frameLength = skipAck2Frame(decryptedPayload);
			break;
		}
		case QUICInitialHeaderView::FrameType::CONNECTION_CLOSE1: {
			frameLength = skipConnectionClose1Frame(decryptedPayload);
			break;
		}
		case QUICInitialHeaderView::FrameType::CONNECTION_CLOSE2: {
			frameLength = skipConnectionClose2Frame(decryptedPayload);
			break;
		}
		case QUICInitialHeaderView::FrameType::PADDING:
			frameLength = std::ranges::find_if(
							  decryptedPayload,
							  [](std::byte b) { return b != std::byte {0x00}; })
				- decryptedPayload.begin();
			break;
		default:
			return std::nullopt;
		}

		if (!frameLength.has_value()) {
			return std::nullopt;
		}
		decryptedPayload = decryptedPayload.subspan(*frameLength);
	}

	if (reassembledFrame->empty()) {
		return std::nullopt;
	}

	return reassembledFrame;
}

bool QUICInitialHeaderView::parseTLSExtensions(TLSParser& parser) noexcept
{
	const bool extensionsParsed = parser.parseExtensions([&](const TLSExtension& extension) {
		if (extension.type == TLSExtensionType::SERVER_NAME && !extension.payload.empty()) {
			const std::optional<TLSParser::ServerNames> parsedServerNames
				= parser.parseServerNames(extension.payload);
			if (parsedServerNames.has_value() && !parsedServerNames->empty()) {
				serverName = std::make_optional<QUICContext::ServerName>();
				std::ranges::copy(
					(*parsedServerNames)[0] | std::views::take(serverName->capacity()),
					std::back_inserter(*serverName));
			}
		}

		if (extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V1
			|| extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS
			|| extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V2) {
			std::optional<TLSParser::UserAgents> parsedUserAgents
				= parser.parseUserAgent(extension.payload);
			if (parsedUserAgents.has_value() && !parsedUserAgents->empty()) {
				userAgent = std::make_optional<QUICContext::UserAgent>();
				std::ranges::copy(
					(*parsedUserAgents)[0] | std::views::take(userAgent->capacity()),
					std::back_inserter(*userAgent));
			}
		}

		if (m_saveWholeTLSExtension || extension.type == TLSExtensionType::ALPN
			|| extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V1
			|| extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS
			|| extension.type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V2) {
			std::ranges::copy(
				extension.payload | std::views::take(QUICContext::MAX_TLS_PAYLOAD_TO_SAVE),
				std::back_inserter(extensionsPayload));
		}

		if (extensionTypes.size() != extensionTypes.capacity()) {
			extensionTypes.push_back(static_cast<uint16_t>(extension.type));
			extensionLengths.push_back(extension.payload.size());
		}

		return true;
	});

	return extensionsParsed;
}

bool QUICInitialHeaderView::parseTLS(const ReassembledFrame& reassembledFrame) noexcept
{
	TLSParser parser;
	if (!parser.parseHelloFromQUIC(toSpan<const std::byte>(reassembledFrame))) {
		return false;
	}

	tlsHandshake = *parser.handshake;

	return parseTLSExtensions(parser);
}

bool QUICInitialHeaderView::parse(
	std::span<const std::byte> payload,
	std::span<const uint8_t> destConnectionId,
	std::span<const std::byte> salt,
	std::span<const std::byte> sample,
	const std::byte headerForm,
	const QUICVersion version,
	const std::byte* encryptedPacketNumber,
	const std::size_t primaryHeaderLength) noexcept
{
	std::optional<QUICInitialSecrets> initialSecrets
		= createInitialSecrets(destConnectionId, salt, version.generation == QUICGeneration::V2);
	if (!initialSecrets.has_value()) {
		// Error, creation of initial secrets failed (client side)
		return false;
	}

	std::span<const std::byte> originalPayload
		= payload.subspan(-primaryHeaderLength, payload.size() + primaryHeaderLength);
	const std::optional<DeobfuscatedHeader> deobfuscatedHeader = decryptInitialHeader(
		originalPayload,
		*initialSecrets,
		sample,
		primaryHeaderLength,
		encryptedPacketNumber);
	if (!deobfuscatedHeader.has_value()) {
		// DEBUG_MSG("Error, header decryption failed (client side)\n");
		return false;
	}

	const std::optional<DecryptedPayload> decryptedPayload = decryptPayload(
		originalPayload.subspan(deobfuscatedHeader->size()),
		*initialSecrets,
		*deobfuscatedHeader);
	if (!decryptedPayload.has_value()) {
		// DEBUG_MSG("Error, payload decryption failed (client side)\n");
		return false;
	}
	std::optional<ReassembledFrame> reassembledFrame
		= reassembleCryptoFrames(toSpan<const std::byte>(*decryptedPayload));
	if (!reassembledFrame.has_value()) {
		// Error, reassembling of crypto frames failed
		return false;
	}
	if (!parseTLS(*reassembledFrame)) {
		// SNI and User Agent Extraction failed
		return false;
	}

	// clientHelloParsed = tlsHandshake.type == TLSHandshake::Type::CLIENT_HELLO;

	return true;
}

std::size_t QUICInitialHeaderView::getLength() const noexcept
{
	return m_size;
}

std::optional<QUICInitialHeaderView> QUICInitialHeaderView::createFrom(
	std::span<const std::byte> payload,
	const std::byte headerForm,
	std::span<const std::byte> salt,
	std::span<const uint8_t> destConnectionId,
	const QUICVersion version,
	const std::size_t primaryHeaderLength) noexcept
{
	auto res = std::make_optional<QUICInitialHeaderView>();

	const std::optional<VariableLengthInt> tokenLength = readQUICVariableLengthInt(payload);
	if (!tokenLength.has_value()) {
		return std::nullopt;
	}
	res->tokenLength = tokenLength->value;
	if (tokenLength->length + tokenLength->value > payload.size()) {
		return std::nullopt;
	}

	const std::optional<VariableLengthInt> restPayloadLength
		= readQUICVariableLengthInt(payload.subspan(tokenLength->length + tokenLength->value));
	if (!restPayloadLength.has_value() || restPayloadLength->value > MAX_BUFFER_SIZE) {
		return std::nullopt;
	}
	res->m_size = restPayloadLength->value + restPayloadLength->length + tokenLength->value
		+ tokenLength->length;
	if (res->m_size > payload.size()) {
		return std::nullopt;
	}

	const std::byte* encryptedPacketNumber
		= payload.data() + tokenLength->length + tokenLength->value + restPayloadLength->length;

	constexpr std::size_t SAMPLE_LENGTH = 16;
	const std::size_t encryptedPacketNumberLength
		= static_cast<std::size_t>(headerForm & std::byte {0b11}) + 1;
	auto sample
		= std::span<const std::byte>(encryptedPacketNumber + sizeof(uint32_t), SAMPLE_LENGTH);

	if (!res->parse(
			payload,
			destConnectionId,
			salt,
			sample,
			headerForm,
			version,
			encryptedPacketNumber,
			primaryHeaderLength)) {
		return std::nullopt;
	}

	return res;
}

} // namespace ipxp::process::quic
