#include "gtest/gtest.h"

#include "../../output/unirec.hpp"

namespace ipxp_test {

using namespace ipxp;

TEST(UnirecOptParser, pluginMap)
{
    UnirecOptParser p;

    EXPECT_THROW(p.parse("p=foo,,,,,,,,"), ParserError);
    EXPECT_THROW(p.parse("p=foo,"), ParserError);

    EXPECT_NO_THROW(p.parse("p=foo"));
    EXPECT_NO_THROW(p.parse("p=foo,bar"));
    EXPECT_NO_THROW(p.parse("p=foo,(bar)"));
    EXPECT_NO_THROW(p.parse("p=(foo)"));
    EXPECT_NO_THROW(p.parse("p=(foo,bar)"));
    EXPECT_NO_THROW(p.parse("p=foo1,(bar1,bar2),foo2"));
    EXPECT_NO_THROW(p.parse("p=(f)"));

    EXPECT_THROW(p.parse("p="), ParserError);
    EXPECT_THROW(p.parse("p=    "), ParserError);
    EXPECT_THROW(p.parse("p=foo,"), ParserError);
    EXPECT_THROW(p.parse("p=,foo"), ParserError);
    EXPECT_THROW(p.parse("p=()"), ParserError);
    EXPECT_THROW(p.parse("p=(,)"), ParserError);
    EXPECT_THROW(p.parse("p=foo,(,bar)"), ParserError);
    EXPECT_THROW(p.parse("p=foo,(bar"), ParserError);
    EXPECT_THROW(p.parse("p=bar),foo"), ParserError);
    EXPECT_THROW(p.parse("p=foo()"), ParserError);
    EXPECT_THROW(p.parse("p=foo,()"), ParserError);
    EXPECT_THROW(p.parse("p=(foo,(bar))"), ParserError);
    EXPECT_THROW(p.parse("p=foo(),bar"), ParserError);
}

TEST(UnirecOptParser, plugins)
{
    UnirecOptParser p;
    EXPECT_NO_THROW(p.parse("p=foo1,(bar1,bar2),foo2"));

    auto m = p.m_ifc_map;
    EXPECT_EQ(m.size(), 3U);
    EXPECT_EQ(m[0][0], "foo1");
    EXPECT_EQ(m[1].size(), 2U);
    EXPECT_EQ(m[1][0], "bar1");
    EXPECT_EQ(m[1][1], "bar2");
    EXPECT_EQ(m[2][0], "foo2");
}

} // namespace ipxp_test

int main(int argc, char** argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
