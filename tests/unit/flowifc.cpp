#include "gtest/gtest.h"
#include <algorithm>

#include "ipfixprobe/flowifc.hpp"

namespace ipxp_test {

using namespace ipxp;

RecordExt* genext(int id)
{
    return new RecordExt(id);
}

class TestExt : public RecordExt {
public:
    static int REGISTERED_ID;

    TestExt()
        : RecordExt(REGISTERED_ID)
    {
    }
};

int TestExt::REGISTERED_ID = -1;

class TestRec
    : public ::testing::Test
    , public Record {
protected:
    std::vector<RecordExt*> m_vec;

    void SetUp()
    {
        m_vec.push_back(genext(1));
        m_vec.push_back(genext(2));
        m_vec.push_back(genext(1));
        m_vec.push_back(genext(3));

        for (auto it : m_vec) {
            add_extension(it);
        }
    }

    void TearDown() { remove_extensions(); }
};

TEST(RecordExt, llistAdd)
{
    RecordExt* head = genext(1);
    head->add_extension(genext(2));
    head->add_extension(genext(3));
    head->add_extension(genext(1));

    std::vector<int> vec = {1, 2, 3};
    std::vector<RecordExt*> exts;
    RecordExt* tmp = head;
    while (tmp) {
        EXPECT_NE(std::find(vec.begin(), vec.end(), tmp->m_ext_id), vec.end());
        if (tmp->m_ext_id == 1) {
            exts.push_back(tmp);
        }
        tmp = tmp->m_next;
    }
    EXPECT_EQ(exts.size(), 2U);
    EXPECT_NE(exts[0], exts[1]);
}

TEST_F(TestRec, add)
{
    RecordExt* tmp = genext(10);
    add_extension(tmp);
    EXPECT_EQ(get_extension(10), tmp);
}

TEST_F(TestRec, get)
{
    EXPECT_EQ(get_extension(1), m_vec[0]);
    EXPECT_NE(get_extension(1), m_vec[2]);
    EXPECT_EQ(get_extension(2), m_vec[1]);
    EXPECT_EQ(get_extension(3), m_vec[3]);

    EXPECT_EQ(get_extension(666), nullptr);
}

TEST_F(TestRec, remove)
{
    remove_extensions();
    EXPECT_EQ(get_extension(1), nullptr);
}

TEST(TestExt, registration)
{
    Record rec;
    TestExt* ext1 = new TestExt();
    rec.add_extension(ext1);
    EXPECT_NE(rec.get_extension(TestExt::REGISTERED_ID), nullptr);

    EXPECT_EQ(get_extension_cnt(), 0);
    int id = register_extension();
    TestExt::REGISTERED_ID = id;
    EXPECT_EQ(get_extension_cnt(), 1);
    EXPECT_EQ(register_extension(), id + 1);

    TestExt* ext2 = new TestExt();
    rec.add_extension(ext2);
    EXPECT_EQ(rec.get_extension(TestExt::REGISTERED_ID), ext2);
    EXPECT_EQ(rec.get_extension(TestExt::REGISTERED_ID)->m_ext_id, id);
}

} // namespace ipxp_test

int main(int argc, char** argv)
{
    // invoking the tests
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
