// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "utiltime.h"

#include "test/test_bitcoin.h"
#include "checkqueue.h"

#include <boost/test/unit_test.hpp>
#include <atomic>

#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <unordered_set>
boost::thread_group threadGroup;
BOOST_FIXTURE_TEST_SUITE(checkqueue_tests, BasicTestingSetup)


static std::atomic<size_t> n;
struct Dummy {
    bool operator()(std::function<void()>& z){
        ++n;
        return true;
    }
    void swap(Dummy& x) {
    };
};
CCheckQueue<Dummy, (size_t) 100000, 16> queue;

BOOST_AUTO_TEST_CASE(test_CheckQueue_PriorityWorkQueue)
{

    CCheckQueue_Helpers::PriorityWorkQueue<decltype(queue)::Proto> work(0, 16);
    auto m = 0;
    work.add(100);
    BOOST_CHECK(!work.empty());
    size_t x = work.pop();
    BOOST_CHECK(x == 0);
    size_t x2 = work.pop();
    BOOST_CHECK(x2 == 16);
    m = 2;
    while(!work.empty()) {
        work.pop();
        ++m;
    } 
    BOOST_CHECK(m == 100);
    work.add(200);
    std::unordered_set<size_t> results;
    while(!work.empty()) {
        results.insert(work.pop());
        ++m;
    }
    for(auto i = 100; i < 200; ++i)
        results.erase(i);
    BOOST_CHECK(results.empty());
    BOOST_CHECK(m == 200);

    work.reset();

    work.add(1000);

    m = 0;
    try {
        for (;;) {
            work.pop();
            ++m;
        }
    } catch (...) {
    }
    BOOST_CHECK(m == 1000);

}

CCheckQueue_Helpers::job_array<decltype(queue)::Proto> jobs;
static std::atomic<size_t> m;
BOOST_AUTO_TEST_CASE(test_CheckQueue_job_array)
{

    for (size_t i = 0; i < decltype(queue)::MAX_JOBS; ++i)
        jobs.reset_flag(i);
    m = 0;
    threadGroup.create_thread([](){
            for (size_t i = 0; i < decltype(queue)::MAX_JOBS; ++i)
            m += jobs.reserve(i) ? 1 : 0;
            });

    threadGroup.create_thread([](){
            for (size_t i = 0; i < decltype(queue)::MAX_JOBS; ++i)
            m += jobs.reserve(i) ? 1 : 0;
            });
    threadGroup.join_all();

    BOOST_CHECK(m == decltype(queue)::MAX_JOBS);

}
CCheckQueue_Helpers::round_barrier<decltype(queue)::Proto> barrier;
BOOST_AUTO_TEST_CASE(test_CheckQueue_round_barrier)
{

    barrier.reset(8);
    for (int i = 0; i < 8; ++i)
    threadGroup.create_thread([=]()
            {
            decltype(barrier)::Cache cache;
            barrier.mark_done(i, cache);
            while (!barrier.load_done(8, cache))
                boost::this_thread::yield();
            }
            );

    threadGroup.create_thread([](){
            });
    threadGroup.join_all();



}



BOOST_AUTO_TEST_CASE(test_CheckQueue_quit)
{

    auto nThreads = 8;
    for (auto i=0; i<nThreads-1; ++i)
        threadGroup.create_thread([=](){queue.Thread(nThreads);});
    queue.quit_queue();
    threadGroup.join_all();
    queue.reset_quit_queue();
    queue.reset_ids();

}


BOOST_AUTO_TEST_CASE(test_CheckQueue_All)
{

    auto nThreads = 8;
    for (auto i=0; i<nThreads-1; ++i)
        threadGroup.create_thread([=](){queue.Thread(nThreads);});
    n = 0;

    {
        CCheckQueueControl<decltype(queue)> control(&queue, nThreads);

        std::vector<Dummy> vChecks;
        vChecks.reserve(100);
        for (auto i=0; i<100; ++i)
            vChecks.push_back(Dummy{});
        for (auto j = 0; j< 100; ++j)
            control.Add(vChecks);
        control.Wait();
    }
    MilliSleep(1000);
    BOOST_TEST_MESSAGE("n was ["<< n<<"]");
    BOOST_CHECK(n == 100*100);
}

BOOST_AUTO_TEST_SUITE_END()
