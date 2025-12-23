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
