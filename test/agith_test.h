#include <gtest/gtest.h>
#include "tool/Log.h"

class AgithTest : public testing::Test {
public:
    AgithTest();

protected:
    static void SetUpTestCase();
    static void TearDownTestCase();
    virtual void SetUp() override;
    virtual void TearDown() override;
};