#include "gtest/gtest.h"

#include "ipfixprobe/byte-utils.hpp"

namespace ipxp_test {

using namespace ipxp;

TEST(swap_uint64, all)
{
    EXPECT_EQ((uint64_t) 0x8877665544332211, swap_uint64(0x1122334455667788));
}

} // namespace ipxp_test

int main(int argc, char** argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
