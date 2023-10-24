#include "gtest/gtest.h"

#include "ipfixprobe/utils.hpp"

namespace ipxp_test {

using namespace ipxp;

TEST(max, all)
{
    EXPECT_EQ(10U, ipxp::max<uint16_t>(5, 10));
    EXPECT_EQ(10U, ipxp::max<uint16_t>(10, 5));
    EXPECT_EQ(10U, ipxp::max<uint32_t>(10, 10));
    EXPECT_EQ(-100, ipxp::max<int>(-100, -101));
}

TEST(bitcount, all)
{
    EXPECT_EQ(0U, bitcount<uint32_t>(0x00));
    EXPECT_EQ(5U, bitcount<uint32_t>(0x1234));
    EXPECT_EQ(4U, bitcount<uint64_t>(0x0F0));
    EXPECT_EQ(1U, bitcount<bool>(true));
}

TEST(parse_range, all)
{
    std::string from;
    std::string to;

    parse_range("10-20", from, to);
    EXPECT_EQ("10", from);
    EXPECT_EQ("20", to);

    parse_range(" \t -10 - 5", from, to);
    EXPECT_EQ("-10", from);
    EXPECT_EQ("5", to);

    parse_range("  -10 - -5", from, to);
    EXPECT_EQ("-10", from);
    EXPECT_EQ("-5", to);

    parse_range("       1   \t -   \n -5    \n", from, to);
    EXPECT_EQ("1", from);
    EXPECT_EQ("-5", to);
}

TEST(trim_str, all)
{
    std::string tmp1 = "   foo bar \t  \n";
    trim_str(tmp1);
    EXPECT_EQ("foo bar", tmp1);

    std::string tmp2 = "foo \t  \n    bar";
    trim_str(tmp2);
    EXPECT_EQ(tmp2, tmp2);
}

TEST(str2num, valid)
{
    EXPECT_EQ(128, str2num<uint8_t>("128"));
    EXPECT_EQ(-10, str2num<int>("-10"));
    EXPECT_FLOAT_EQ(6.666, str2num<float>("6.666"));
    EXPECT_EQ((uint32_t) 0xDEADBEEF, str2num<uint32_t>(" \t \n  0xDEADBEEF"));
}

TEST(str2num, invalid)
{
    EXPECT_THROW(str2num<unsigned>(""), std::invalid_argument);
    EXPECT_THROW(str2num<unsigned>("-1"), std::invalid_argument);
    EXPECT_THROW(str2num<uint8_t>("256"), std::invalid_argument);
    EXPECT_THROW(
        str2num<uint64_t>("2000000000000000000000000000000000000000000"),
        std::invalid_argument);
    EXPECT_THROW(str2num<uint32_t>("  25  v "), std::invalid_argument);
}

TEST(str2bool, all)
{
    EXPECT_TRUE(str2bool("yEs"));
    EXPECT_TRUE(str2bool("y"));
    EXPECT_TRUE(str2bool("true"));
    EXPECT_TRUE(str2bool("truE"));
    EXPECT_TRUE(str2bool("t"));
    EXPECT_TRUE(str2bool("1"));
    EXPECT_TRUE(str2bool("on"));

    EXPECT_FALSE(str2bool("no"));
    EXPECT_FALSE(str2bool("0"));
    EXPECT_FALSE(str2bool("false"));
    EXPECT_FALSE(str2bool("f"));
    EXPECT_FALSE(str2bool("off"));
    EXPECT_FALSE(str2bool("abc"));
}

} // namespace ipxp_test

int main(int argc, char** argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
