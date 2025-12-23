/**
 * @file
 * @brief Tests for outputFieldConfigurationParser.
 * @author Damir Zainullin <zaidamilda@gmail.com>
 * @date 2025
 *
 * @copyright Copyright (c) 2025 CESNET, z.s.p.o.
 */

#include <fstream>
#include <ranges>
#include <set>
#include <string_view>
#include <vector>

#include <fieldGroup.hpp>
#include <fieldHandler.hpp>
#include <fieldHandlersEnum.hpp>
#include <fieldManager.hpp>
#include <gtest/gtest.h>
#include <outputConfigurationParser.hpp>

using namespace ipxp::process;
using namespace ipxp;

static auto dummyGetter = [](const void*) { return 0; };

enum class QUICFields { QUIC_F1, QUIC_F2, FIELDS_SIZE };

enum class TLSFields { TLS_F1, TLS_F2, FIELDS_SIZE };

void addDummyOutputFields(FieldManager& fieldManager)
{
	FieldGroup quicSchema = fieldManager.createFieldGroup("quic");
	FieldHandlers<QUICFields> quicFieldHandlers;

	quicFieldHandlers.insert(
		QUICFields::QUIC_F1,
		quicSchema.addScalarField("QUIC_F1", dummyGetter));
	quicFieldHandlers.insert(
		QUICFields::QUIC_F2,
		quicSchema.addScalarField("QUIC_F2", dummyGetter));

	FieldGroup tlsSchema = fieldManager.createFieldGroup("tls");
	FieldHandlers<TLSFields> tlsFieldHandlers;

	tlsFieldHandlers.insert(TLSFields::TLS_F1, tlsSchema.addScalarField("TLS_F1", dummyGetter));
	tlsFieldHandlers.insert(TLSFields::TLS_F2, tlsSchema.addScalarField("TLS_F2", dummyGetter));
}

struct KeyFields {
	std::string_view group;
	std::string_view name;

	constexpr bool operator<(const KeyFields& other) const noexcept
	{
		return std::tie(group, name) < std::tie(other.group, other.name);
	}

	constexpr bool operator==(const KeyFields& other) const noexcept
	{
		return std::tie(group, name) == std::tie(other.group, other.name);
	}
};

std::set<KeyFields> extractKeyFields(const std::vector<const FieldDescriptor*>& descriptors)
{
	return descriptors | std::views::transform([](const FieldDescriptor* desc) {
			   return KeyFields {desc->getGroup(), desc->getName()};
		   })
		| std::ranges::to<std::set>();
}

std::set<KeyFields> getKeyOutputFieldsFromConfig(std::string_view configFilePath)
{
	std::ifstream configFile(configFilePath.data());
	if (!configFile.is_open()) {
		throw std::invalid_argument(
			"Could not open configuration file: " + std::string(configFilePath));
	}
	const std::string configuration(
		(std::istreambuf_iterator<char>(configFile)),
		std::istreambuf_iterator<char>());

	FieldManager fieldManager;
	addDummyOutputFields(fieldManager);
	OutputConfigurationParser outputParser(configuration);
	return extractKeyFields(outputParser.getOutputFields(fieldManager.getUniflowForwardFields()));
}

TEST(TestOutputFieldConfigurationParser, TestAll1)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/all1.cfg"),
		(std::set<KeyFields> {
			{"quic", "QUIC_F1"},
			{"quic", "QUIC_F2"},
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestAll2)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/all2.cfg"),
		(std::set<KeyFields> {
			{"quic", "QUIC_F1"},
			{"quic", "QUIC_F2"},
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestAll3)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/all3.cfg"),
		(std::set<KeyFields> {
			{"quic", "QUIC_F1"},
			{"quic", "QUIC_F2"},
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestAll4)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/all4.cfg"),
		(std::set<KeyFields> {
			{"quic", "QUIC_F1"},
			{"quic", "QUIC_F2"},
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestAll5)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/all5.cfg"),
		(std::set<KeyFields> {
			{"quic", "QUIC_F1"},
			{"quic", "QUIC_F2"},
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestEmpty1)
{
	EXPECT_TRUE(getKeyOutputFieldsFromConfig(
					"../../../../tests/unit/outputConfigurationParser/inputs/empty1.cfg")
					.empty());
}

TEST(TestOutputFieldConfigurationParser, TestEmpty2)
{
	EXPECT_TRUE(getKeyOutputFieldsFromConfig(
					"../../../../tests/unit/outputConfigurationParser/inputs/empty2.cfg")
					.empty());
}

TEST(TestOutputFieldConfigurationParser, TestEmpty3)
{
	EXPECT_TRUE(getKeyOutputFieldsFromConfig(
					"../../../../tests/unit/outputConfigurationParser/inputs/empty3.cfg")
					.empty());
}

TEST(TestOutputFieldConfigurationParser, TestTLS1)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/tls1.cfg"),
		(std::set<KeyFields> {
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}

TEST(TestOutputFieldConfigurationParser, TestTLS2)
{
	EXPECT_EQ(
		getKeyOutputFieldsFromConfig(
			"../../../../tests/unit/outputConfigurationParser/inputs/tls2.cfg"),
		(std::set<KeyFields> {
			{"tls", "TLS_F1"},
			{"tls", "TLS_F2"},
		}));
}