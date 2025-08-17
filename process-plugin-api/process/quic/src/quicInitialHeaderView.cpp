#include "quicInitialHeaderView.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string_view>
#include <boost/container/static_vector.hpp>
#include <algorithm>
#include <arpa/inet.h>

#include <common/utils/spanUtils.hpp>
#include "quicVariableInt.hpp"

#include "opensslContext.hpp"

namespace ipxp
{

using ExpandedLabel = boost::container::static_vector<std::byte, 
    QUICInitialHeaderView::MAX_EXPANDED_LABEL_LENGTH>;

template<uint16_t DesiredLength>
constexpr static
ExpandedLabel expandLabel(
	std::string_view prefix,
	std::string_view label) noexcept
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
    res.push_back(std::byte{convertedDesiredLength >> 8});
    res.push_back(std::byte{convertedDesiredLength & 0xFF});

    res.insert(res.end(), prefix.begin(), prefix.end());

    res.insert(res.end(), label.begin(), label.end());

    // Context length is always zero
    res.push_back(std::byte{0});

    return res;
}

template<std::size_t BufferSize>
constexpr static
std::optional<std::array<std::byte, BufferSize>> 
deriveFromSecret(
	std::span<const std::byte> secret,
	std::span<const std::byte> expandedLabel)
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
            expandedLabel.data(), 
            expandedLabel.size()) ||
        // key initialization failed
        !EVP_PKEY_CTX_set1_hkdf_key(
            keyContext.get(), 
            secret.data(), 
            HASH_SHA2_256_LENGTH) ||
        // HKDF-Expand derivation failed
        !EVP_PKEY_derive(keyContext.get(), derived->data(), &derivedLength)) {
		return std::nullopt;
	}
	return derived;
}

constexpr static
std::optional<QUICInitialSecrets> 
deriveSecrets(std::span<const std::byte> secret, 
    const bool isSecondGeneration) noexcept
{
    auto res = std::make_optional<QUICInitialSecrets>();

    const std::string_view keyLabel 
        = isSecondGeneration ? "quicv2 key" : "quic key";
    const std::string_view initialVectorLabel 
        = isSecondGeneration ? "quicv2 iv" : "quic iv";
    const std::string_view headerProtectionLabel 
        = isSecondGeneration ? "quicv2 hp" : "quic hp";
		
    // use HKDF-Expand to derive other secrets
    const ExpandedLabel expandedKey = 
        expandLabel<AES_128_KEY_LENGTH>("tls13 ", keyLabel);
    const std::optional<std::array<std::byte, AES_128_KEY_LENGTH>> keyDerived 
        = deriveFromSecret<AES_128_KEY_LENGTH>(
            secret,
            expandedKey);
    if (!keyDerived) {
        return std::nullopt;
    }

    res->key = *keyDerived;

    const ExpandedLabel expandedInitialVector = 
        expandLabel<TLS13_AEAD_NONCE_LENGTH>("tls13 ", initialVectorLabel);
    const std::optional<std::array<std::byte, TLS13_AEAD_NONCE_LENGTH>> 
    initialVectorDerived = deriveFromSecret<TLS13_AEAD_NONCE_LENGTH>(
            secret,
            expandedInitialVector);
    if (!initialVectorDerived) {
        return std::nullopt;
    }

    res->initialVector = *initialVectorDerived;

    const ExpandedLabel expandedHeaderProtection = 
        expandLabel<AES_128_KEY_LENGTH>("tls13 ", headerProtectionLabel);
    const std::optional<std::array<std::byte, AES_128_KEY_LENGTH>> 
    headerProtectionDerived = deriveFromSecret<AES_128_KEY_LENGTH>(
            secret,
            expandedHeaderProtection);
    if (!headerProtectionDerived) {
        return std::nullopt;
    }

    res->headerProtection = *headerProtectionDerived;

	return res;
}


constexpr std::optional<QUICInitialSecrets>
createInitialSecrets(std::span<const std::byte> destConnectionId, 
    std::span<const std::byte> salt) noexcept
{
	// Set DCID if not set by previous packet
	/*if (initial_dcid_len == 0) {
		initial_dcid_len = dcid_len;
		initial_dcid = (uint8_t*) dcid;
	}*/

	std::array<std::byte, HASH_SHA2_256_LENGTH> extractedSecret = {0};
	std::size_t extractedSecretLength = HASH_SHA2_256_LENGTH;

    std::array<std::byte, HASH_SHA2_256_LENGTH> expandedSecret = {0};
	size_t expandedSecretLength = HASH_SHA2_256_LENGTH;


	// HKDF-Extract
	//std::unique_ptr<EVP_PKEY_CTX> publicKeyContext 
	auto publicKeyContext = createKeyContext();

    const ExpandedLabel expandedLabel 
        = expandLabel<QUICInitialHeaderView::SHA2_256_LENGTH>(
            "tls13 ", "client in");

        ///context initialization
	if (!EVP_PKEY_derive_init(publicKeyContext.get()) ||
        //mode initialization
        !EVP_PKEY_CTX_hkdf_mode(
            publicKeyContext.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) ||
        // message digest initialization
        !EVP_PKEY_CTX_set_hkdf_md(
            publicKeyContext.get(), EVP_sha256()) ||
        // salt initialization
        !EVP_PKEY_CTX_set1_hkdf_salt(
            publicKeyContext.get(), 
            salt.data(), 
            salt.size()) ||
        // key initialization
        !EVP_PKEY_CTX_set1_hkdf_key(
            publicKeyContext.get(), 
            destConnectionId.data(), 
            destConnectionId.size()) ||
        // HKDF-Extract derivation
        !EVP_PKEY_derive(
            publicKeyContext.get(), reinterpret_cast<uint8_t*>(
                extractedSecret.data()), &secretLength) ||
        // Expand context initialization
        !EVP_PKEY_derive_init(publicKeyContext.get()) ||
        // Expand mode initialization
        !EVP_PKEY_CTX_hkdf_mode(
            publicKeyContext.get(), 
            EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) ||
        // Expand message digest initialization
        !EVP_PKEY_CTX_set_hkdf_md(publicKeyContext.get(), EVP_sha256()) ||
        // Expand info initialization
        !EVP_PKEY_CTX_add1_hkdf_info(
            publicKeyContext.get(), 
            expandedLabel.data(), 
            expandedLabel.size()) ||
        // Expand key initialization
        !EVP_PKEY_CTX_set1_hkdf_key(
            publicKeyContext.get(), 
            extractedSecret.data(), 
            extractedSecretLength) ||
        // HKDF-Expand derivation
        !EVP_PKEY_derive(
            publicKeyContext.get(), 
            expandedSecret.data(), 
            &expandedSecretLength)) {
		return std::nullopt;
	}

    return deriveSecrets(toSpan(expandedSecret));
}

constexpr static
std::optional<boost::container::static_vector<std::byte, QUICInitialHeaderView::SAMPLE_LENGTH>> 
QUICParser::encryptSample(const QUICInitialSecrets& initialSecrets, 
    std::span<const std::byte> sample)
{
    auto plaintext = std::make_optional<boost::container::static_vector<std::byte, 
        QUICInitialHeaderView::SAMPLE_LENGTH>>();

    auto cipherContext = createCipherContext();

        // context creation failed
	if (!cipherContext ||
        // context initialization failed
        !EVP_EncryptInit_ex(
            cipherContext.get(), 
            EVP_aes_128_ecb(), 
            nullptr, 
            initialSecrets.headerProtection.data(), 
            nullptr)) {
		return std::nullopt;
	}

	// we need to disable padding so we can use EncryptFinal
	EVP_CIPHER_CTX_set_padding(cipherContext.get(), 0);

	std::size_t encryptedLength = 0;
        //decrypting header
	if (!EVP_EncryptUpdate(
            cipherContext.get(), 
            plaintext.data(), 
            &encryptedLength, 
            sample.data(), 
            sample.size()) ||
        // final header decryption
		!EVP_EncryptFinal_ex(
            cipherContext.get(), 
            plaintext.data() + encryptedLength, 
            &encryptedLength)) {
		return std::nullopt;
	}

    plaintext.reserve(encryptedLength);
	return plaintext;
}

constexpr static
bool decryptInitialHeader(const QUICInitialSecrets& initialSecrets, 
    std::span<const std::byte> sample, const std::byte formHeader,
    const std::byte* encryptedPacketNumber) noexcept
{
	//uint8_t plaintext[SAMPLE_LENGTH];
	std::array<std::byte, 5> mask = {0};
	std::array<std::byte, 4> full_pkn = {0};
	//std::byte first_byte = 0;
	uint32_t packet_number = 0;

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
	std::optional<boost::container::static_vector<std::byte, QUICInitialHeaderView::SAMPLE_LENGTH>> 
    plaintext = encryptSample(initialSecrets, sample);
    if (!plaintext.has_value()) {
		return false;
	}

    std::copy(plaintext.data(), plaintext.data() + mask.size(), mask.begin());

	const std::byte deobfuscatedFormHeader = formHeader ^ (mask[0] & std::byte{0x0f});
	const uint8_t packetNumberLength 
    = (static_cast<uint8_t>(deobfuscatedFormHeader) & 0x03) + 1;

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

    std::transform(encryptedPacketNumber, encryptedPacketNumber + packetNumberLength, 
        [&, index = 0](const std::byte obfuscatedByte) mutable {
            packetNumberBytes[index + 4 - packetNumberLength] 
                = obfuscatedByte ^ mask[index + 1];
            index++;
        });

    return ntohl(
        *reinterpret_cast<const uint32_t*>(packetNumberBytes.data()));

	// adjust nonce for payload decryption
	// https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
	//  The exclusive OR of the padded packet number and the IV forms the AEAD nonce

    const uint64_t* initialVectorEnd = initialSecrets.initialVector.data() 
        + initialSecrets.initialVector.size() - sizeof(uint64_t);

	*initialVectorEnd = htobe64(be64toh(*initialVectorEnd) ^ packet_number);

    return true;
}

constexpr static std::optional<std::array<std::byte, ReassembledFrame::capacity()>>
decryptPayload(std::span<const std::byte> encryptedPayload) noexcept
{
    const std::array<std::byte, 16> authTag;

    if (encryptedPayload.size() <= authTag.size()) {
        return std::nullopt;
    }
	/* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */
    if (encryptedPayload.size() > ReassembledFrame::capacity()) {
		return std::nullopt;
	}

	std::size_t decryptedLength;

    auto decryptedPayload = std::make_optional<std::array<std::byte, 
        ReassembledFrame::capacity()>>();

	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
	// "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger
	// than their input." adjust length because last 16 bytes are authentication tag
	//payload_len -= 16;
	//payload_len_offset = 16;

    std::copy(encryptedPayload.data() + encryptedPayload.size() - 16, 
        encryptedPayload.data() + encryptedPayload.size(), authTag.begin());

    auto cipherContext = createCipherContext();

	if (!cipherContext || 
        // context initialization
        !EVP_DecryptInit_ex(
            cipherContext.get(), 
            EVP_aes_128_gcm(), 
            nullptr, nullptr, nullptr) || 
        // setting NONCE length
        !EVP_CIPHER_CTX_ctrl(
            cipherContext.get(), 
            EVP_CTRL_AEAD_SET_IVLEN, 
            TLS13_AEAD_NONCE_LENGTH, 
            nullptr) || 
        // setting KEY and NONCE
        !EVP_DecryptInit_ex(
            cipherContext.get(), 
            nullptr, 
            nullptr, 
            initial_secrets.key, 
            initial_secrets.iv) || 
        // initializing authenticated data
        !EVP_DecryptUpdate(
            cipherContext.get(), 
            nullptr, 
            &decryptedLength, 
            header, 
            header_len) || 
        // decrypting payload
        !EVP_DecryptUpdate(
            cipherContext.get(), 
            decryptedPayload.data(), 
            &decryptedLength, 
            payload, 
            payload_len) || 
        // TAG check
        !EVP_CIPHER_CTX_ctrl(
            cipherContext.get(),
            EVP_CTRL_AEAD_SET_TAG, 
            authTag.size(), 
            authTag.data()) || 
        // final payload decryption
        !EVP_DecryptFinal_ex(
            cipherContext.get(), 
            decryptedPayload.data() + decryptedLength, 
            &decryptedLength)) {
		return std::nullopt;
	}

	return decryptedPayload;
}

constexpr static
std::span<const std::byte> 
getCryptoData(std::span<const std::byte> payload) noexcept
{
    const std::optional<VariableLengthInt> frameOffset
        = readQUICVariableLengthInt(payload);
    if (!frameOffset.has_value()) {
		return std::nullopt;
	}

    const std::size_t lengthOffset = frameOffset->length;
    const std::optional<VariableLengthInt> length
        = readQUICVariableLengthInt(payload.subspan(lengthOffset));
    if (!length.has_value()) {
		return std::nullopt;
	}

    return std::span<const std::byte>(payload.data() + 
        lengthOffset + length->length, length->value);
}

constexpr static
std::optional<std::size_t> skipAck1Frame(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	const std::optional<VariableLengthInt> lastAcknowledged
        = readQUICVariableLengthInt(payload);
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

	const std::size_t firstAckRangeOffset 
        = ackRangeCountOffset + ackRangeCount->length;
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

constexpr static
std::optional<std::size_t> skipAck2Frame(std::span<const std::byte> payload) noexcept
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

    const std::size_t congestionExperiencedOffset 
        = ect1Offset + ect1PacketCount->length;
    const std::optional<VariableLengthInt> congestionExperiencedCount
        = readQUICVariableLengthInt(payload.subspan(congestionExperiencedOffset));
    if (!congestionExperiencedCount.has_value()) {
		return std::nullopt;
	}

	return congestionExperiencedOffset + congestionExperiencedCount->length;
}

constexpr static
std::optional<std::size_t> skipConnectionClose1(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
    const std::optional<VariableLengthInt> errorCode 
        = readQUICVariableLengthInt(payload);
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

	return reasonPhraseLengthOffset 
        + reasonPhraseLength->length + reasonPhraseLength.value;
}

constexpr static
std::optional<std::size_t> skipConnectionClose2(std::span<const std::byte> payload) noexcept
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	const std::optional<VariableLengthInt> errorCode 
        = readQUICVariableLengthInt(payload);
    if (!errorCode.has_value()) {
		return std::nullopt;
	}

    const std::size_t reasonPhraseLengthOffset = errorCode->length + frameType->length;
    const std::optional<VariableLengthInt> reasonPhraseLength
        = readQUICVariableLengthInt(payload.subspan(reasonPhraseLengthOffset));
    if (!reasonPhraseLength.has_value()) {
		return std::nullopt;
	}

	return reasonPhraseLengthOffset 
        + reasonPhraseLength->length + reasonPhraseLength.value;
}


constexpr static
std::optional<ReassembledFrame> 
reassembleCryptoFrames(std::span<const std::byte> decryptedPayload) noexcept
{
    auto reassembledFrame = std::make_optional<ReassembledFrame>();

	while (!decryptedPayload.empty()) {
		// https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
		// only those frames can occure in initial packets
		std::optional<std::size_t> frameLength;
        const FrameType frameType = static_cast<FrameType>(decryptedPayload[0]);
        decryptedPayload = decryptedPayload.subspan(sizeof(FrameType));
        
        switch (frameType)
        {
        case FrameType::CRYPTO:
            std::optional<std::span<const std::byte>> cryptoData 
                = getCryptoData(decryptedPayload);
            if (!cryptoData.has_value() || reassembledFrame->size() 
                + cryptoData->size() > reassembledFrame->capacity()) {
                return std::nullopt;
            }
            const std::size_t sizeToCopy = std::min(
                cryptoData->size(), reassembledFrame->capacity() - reassembledFrame->size());
            reassembledFrame->insert(
                cryptoData->begin(), cryptoData->begin() + sizeToCopy);

            frameLength = cryptoData->data() - 
                decryptedPayload.data() + cryptoData->size();
        case FrameType::ACK1:
            frameLength = skipAck1(decryptedPayload);
            break;
        case FrameType::ACK2:
            frameLength = skipAck2(decryptedPayload);
            break;
        case FrameType::CONNECTION_CLOSE1:
            frameLength = skipConnectionClose1(decryptedPayload);
            break;
        case FrameType::CONNECTION_CLOSE2:
            frameLength = skipConnectionClose2(decryptedPayload);
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

constexpr
bool QUICParser::parseTLSExtensions(TLSParser& parser)
{
	const bool extensionsParsed = parser.parseExtensions(
        [&](const Extension& extension) {
        m_initialHeaderEnd = extension.payload.end();

		if (extension.type == TLSExtensionType::SERVER_NAME && 
            !extension.payload.empty()) {
            const std::optional<ServerNames> parsedServerNames
                = parser.parseServerNames(extension.payload);
            if (parsedServerNames.has_value() && !parsedServerNames->empty()) {
                serverName.clear();
                std::ranges::copy(parsedServerNames[0] |
                    std::views::take(serverName.capacity()),
                std::back_inserter(serverName));
            }
		}

        if (extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V1 ||
			extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS ||
			extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V2) {
            std::optional<TLSParser::UserAgents> parsedUserAgents = 
                parser.parseUserAgent(extension.payload);
            if (parsedUserAgents.has_value() && !parsedUserAgents->empty()) {
                userAgent.clear()
                std::ranges::copy(parsedUserAgents[0] |
                    std::views::take(userAgent.capacity()),
                std::back_inserter(userAgent)); 
            } 
		}

        if (m_saveWholeTLSExtension
            || extension_type == TLSExtensionType::ALPN
            || extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V1
            || extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS
            || extension_type == TLSExtensionType::QUIC_TRANSPORT_PARAMETERS_V2) {
            std::ranges::copy(extension.payload |
                std::views::take(QUICExport::MAX_TLS_PAYLOAD_TO_SAVE),
                std::back_inserter(extensionsPayload));
        }

        if (!m_exportData.extensionTypes.full()) {
			m_exportData.extensionTypes.push_back(extension.type);
			m_exportData.extensionLengths.push_back(extension.payload.size());
		}
	});

	return extensionsParsed;
}

constexpr
bool QUICInitialHeaderView::parseTLS(const ReassembledFrame& reassembledFrame)
{
    TLSParser parser;
	if (!parser.parseHelloFromQUIC(toSpan(reassembledFrame))) {
		return false;
	}

    tlsHandshake = parser.handshake;

    // TODO set m_initialHeaderEnd if extensions are empty

	return parseTLSExtensions(parser);
}

constexpr
bool QUICInitialHeaderView::parse(std::span<const std::byte> destConnectionId, 
    std::span<const std::byte> salt,
    const PacketType packetType,
    std::span<const std::byte> sample,
    const std::byte headerForm,
    const std::byte* encryptedPacketNumber) noexcept
{
    const std::optional<QUICInitialSecrets> initialSecrets 
        = createInitialSecrets(destConnectionId, salt);
	if (!initialSecrets.has_value()) {
		// Error, creation of initial secrets failed (client side)
		return false;
	}
	if (!decryptInitialHeader(*initialSecrets, sample, 
            headerForm, encryptedPacketNumber)) {
		DEBUG_MSG("Error, header decryption failed (client side)\n");
		return false;
	}
	if (!decryptPayload()) {
		DEBUG_MSG("Error, payload decryption failed (client side)\n");
		return false;
	}
    std::optional<ReassembledFrame> reassembledFrame 
        = reassembleCryptoFrames(decryptedPayload);
	if (!reassembledFrame.has_value()) {
		// Error, reassembling of crypto frames failed
		return false;
	}
	if (!parseTLS(*reassembledFrame)) {
		// SNI and User Agent Extraction failed
		return false;
	}

	//clientHelloParsed = tlsHandshake.type == TLSHandshake::Type::CLIENT_HELLO;

	return true;
}

constexpr
std::size_t getLength() const noexcept
{
    return m_size;
}

constexpr
std::optional<QUICInitialHeaderView> QUICInitialHeaderView::createFrom(
    std::span<const std::byte> payload,
    const PacketType packetType,
    const std::byte headerForm,
    std::span<const std::byte> salt,
    std::span<const std::byte> destConnectionId) noexcept
{
    tokenLength = readQUICVariableLengthInt(payload);
	if (!tokenLength.has_value()) {
		return false;
	}

	const std::optional<VariableLengthInt> restPayloadLength 
		= readQUICVariableLengthInt(payload.subspan(tokenLength->length));
	if (!restPayloadLength.has_value() ||
		restPayloadLength->value > MAX_PAYLOAD_BUFFER_SIZE) {
		return false;
	}
    m_size = restPayloadLength->value + restPayloadLength->length
        + tokenLength->value + tokenLength->length;
    if (m_size > payload.size()) {
        return false;
    } 

    const std::byte* encryptedPacketNumber = payload.data() + tokenLength->length
    + tokenLength->value + restPayloadLength->length;

    const std::size_t encryptedPacketNumberLength = headerForm & std::byte{0b11};
    std::span<const std::byte> sample 
        = encryptedPacketNumber + encryptedPacketNumberLength;

	parse(destConnectionId, salt, packetType, sample, headerForm, encryptedPacketNumber);
}



} // namespace ipxp
