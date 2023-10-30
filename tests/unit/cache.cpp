#include <algorithm>
#include "gtest/gtest.h"

#include "storage/cache.hpp"
#include "storage/old_cache.hpp"
#include "fstream"
#include <sys/stat.h>
#include <limits.h>

namespace ipxp_test {

using namespace ipxp;

TEST(TestCaches,compareResult)
{
    auto list ={"dns","mixed","bstats","dnssd","tls","sip","ssdp",
                "ovpn","vlan","wg","http","rtsp","quic_initial-sample",
                "smtp","idpcontent","arp","ntp","netbios"};
    for(const auto& filename : list){
        system((std::string("../../ipfixprobe -i 'pcap;file=../../pcaps/") + filename
            +".pcap' -o 'text' -s old_cache > old_cache.res").c_str());
        system((std::string("../../ipfixprobe -i 'pcap;file=../../pcaps/") + filename
            + ".pcap' -o 'text' -s cache > cache.res").c_str());
        std::ifstream f1("cache.res"),f2("old_cache.res");
        std::cout<<"Testing:" << filename  << "\n";
        if (!f1 || !f2)
            FAIL() << "Some file(s) wasn't created\n";
        std::string str1,str2;
        while(true){
            std::getline(f1,str1);
            std::getline(f2,str2);
            EXPECT_EQ(str1, str2) << "Mismatch\n";
            if (f2.eof() && f1.eof())
                break;
            if (f1.bad() || f2.bad() || (f1.eof() && !f2.eof()) || (f2.eof() && !f1.eof()))
                FAIL() << "Error\n";
        }
        f1.close();
        f2.close();
    }
}

}

int main(int argc, char **argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

