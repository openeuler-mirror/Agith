#include <gtest/gtest.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // 关闭内存限制
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    ::testing::InitGoogleTest(&argc, argv);
    // ::testing::GTEST_FLAG(filter) = "AgithTest.*";
    return RUN_ALL_TESTS();
}