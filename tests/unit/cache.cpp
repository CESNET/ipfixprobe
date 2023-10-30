#include <algorithm>
#include "gtest/gtest.h"

#include "ipfixprobe/flowifc.hpp"

namespace ipxp_test {

using namespace ipxp;

RecordExt *genext(int id)
{
   return new RecordExt(id);
}

class TestExt : public RecordExt
{
public:
   static int REGISTERED_ID;

   TestExt() : RecordExt(REGISTERED_ID) {}
};

int TestExt::REGISTERED_ID = -1;

class TestRec : public::testing::Test, public Record
{
protected:
   std::vector<RecordExt *> m_vec;

   void SetUp() {
      m_vec.push_back(genext(1));
      m_vec.push_back(genext(2));
      m_vec.push_back(genext(1));
      m_vec.push_back(genext(3));

      for (auto it : m_vec) {
         add_extension(it);
      }
   }

   void TearDown() {
      remove_extensions();
   }
};


TEST(TestExt, registration)
{
   EXPECT_EQ(0, 1);
}

}

int main(int argc, char **argv)
{
   // invoking the tests
   ::testing::InitGoogleTest(&argc, argv);
   return RUN_ALL_TESTS();
}

