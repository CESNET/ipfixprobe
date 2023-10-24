#include "gtest/gtest.h"

#include "ipfixprobe/options.hpp"
#include "ipfixprobe/utils.hpp"

namespace ipxp_test {

using namespace ipxp;

class TestParser1 : public OptionsParser {
public:
    std::vector<std::string> m_vec;
    uint32_t m_num;
    bool m_bool;
    std::string m_str;

    TestParser1()
        : OptionsParser("testparser", "test parser description")
        , m_num(0)
        , m_bool(false)
        , m_str("")
    {
        m_delim = ' ';

        register_option(
            "-v",
            "--vec",
            "STR",
            "vector param",
            [this](const char* arg) {
                m_vec.push_back(arg);
                return true;
            },
            OptionFlags::RequiredArgument);
        register_option(
            "-n",
            "--num",
            "NUM",
            "num param",
            [this](const char* arg) {
                try {
                    m_num = str2num<decltype(m_num)>(arg);
                } catch (std::invalid_argument& e) {
                    return false;
                }
                return true;
            },
            OptionFlags::RequiredArgument);
        register_option(
            "-s",
            "--str",
            "STR",
            "str param",
            [this](const char* arg) {
                m_str = arg ? arg : "";
                return true;
            },
            OptionFlags::OptionalArgument);
        register_option(
            "-b",
            "--bool",
            "",
            "bool param",
            [this](const char* arg) {
                m_bool = true;
                return true;
            },
            OptionFlags::NoArgument);
    }
};

class TestParser2
    : public ::testing::Test
    , public OptionsParser {
protected:
    void SetUp() {}

    void TearDown() {}
};

TEST(OptionsParser, all)
{
    OptionsParser p("testparser", "dummy parser desc");
}

TEST(TestParser1, argline)
{
    TestParser1 p;
    const char* arg[] = {"-s", "50", "-n", "100"};
    EXPECT_NO_THROW(p.parse(4, arg));

    EXPECT_EQ(p.m_str, "50");
    EXPECT_EQ(p.m_num, 100U);
}

TEST(TestParser1, arglineError)
{
    TestParser1 p;
    const char* arg[] = {"-s", "50", "-n"};
    EXPECT_THROW(p.parse(3, arg), ParserError);

    EXPECT_NO_THROW(p.parse(0, NULL));
    EXPECT_THROW(p.parse(5, NULL), std::runtime_error);

    const char* arg2[] = {"-s", "50", "-p", "-n", "100"};
    EXPECT_THROW(p.parse(5, arg2), ParserError);
}

TEST(TestParser1, argstr)
{
    TestParser1 p;
    EXPECT_NO_THROW(p.parse("-s=/path/str      --num=1024"));
    EXPECT_EQ("/path/str", p.m_str);
    EXPECT_EQ(1024U, p.m_num);

    EXPECT_EQ(false, p.m_bool);
    EXPECT_NO_THROW(p.parse("-n=0xFF -b"));
    EXPECT_EQ(255U, p.m_num);
    EXPECT_EQ(true, p.m_bool);

    EXPECT_NO_THROW(p.parse("-v=1 -v=2 --vec=3 -v=4"));
    EXPECT_EQ(p.m_vec.size(), 4U);
    std::vector<std::string> ref = {"1", "2", "3", "4"};
    EXPECT_EQ(p.m_vec, ref);

    EXPECT_NO_THROW(p.parse("-v -v"));
}

TEST(TestParser1, argstrError)
{
    TestParser1 p;
    EXPECT_THROW(p.parse("--num=-10"), ParserError);
    EXPECT_THROW(p.parse("--num"), ParserError);
    EXPECT_THROW(p.parse("--num="), ParserError);
    EXPECT_THROW(p.parse("-b=ABC"), ParserError);

    EXPECT_NO_THROW(p.parse(""));
    EXPECT_NO_THROW(p.parse(NULL));
}

TEST_F(TestParser2, invalidOptions)
{
    auto func = [this](const char* arg) { return true; };
    EXPECT_THROW(
        register_option("", "", "", "", func, OptionFlags::NoArgument),
        std::runtime_error);
    EXPECT_THROW(
        register_option("-s", "", "", "desc", func, OptionFlags::NoArgument),
        std::runtime_error);
    EXPECT_THROW(
        register_option("", "--long", "", "desc", func, OptionFlags::NoArgument),
        std::runtime_error);
    EXPECT_THROW(
        register_option("-d", "--desc", "", "", func, OptionFlags::NoArgument),
        std::runtime_error);
}

TEST_F(TestParser2, dupOptions)
{
    auto func = [this](const char* arg) { return true; };
    EXPECT_NO_THROW(register_option("a", "aaa", "", "a param", func, OptionFlags::NoArgument));
    EXPECT_NO_THROW(register_option("b", "bbb", "", "b param", func, OptionFlags::NoArgument));
    EXPECT_NO_THROW(register_option("c", "ccc", "", "c param", func, OptionFlags::NoArgument));
    EXPECT_THROW(
        register_option("b", "ddd", "", "d param", func, OptionFlags::NoArgument),
        std::runtime_error);
    EXPECT_THROW(
        register_option("e", "ccc", "", "e param", func, OptionFlags::NoArgument),
        std::runtime_error);
}

} // namespace ipxp_test

int main(int argc, char** argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
