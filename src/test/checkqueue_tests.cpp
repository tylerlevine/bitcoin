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
CCheckQueue<Dummy, 100000, 16> queue;

BOOST_AUTO_TEST_CASE(test_CheckQueue_PriorityWorkQueue)
{

    CCheckQueue_Helpers::PriorityWorkQueue<decltype(queue)::Proto> work(0, 16);
    n = 0;

    work.add(100);
    assert(!work.empty());
    size_t x = work.get_one();
    assert(x == 0);
    size_t x2 = work.get_one();
    assert(x2 == 16);
    auto n = 2;
    while(!work.empty()) {
        work.get_one();
        ++n;
    }
    assert(n == 100);
    work.add(200);
    std::unordered_set<size_t> results;
    while(!work.empty()) {
        results.insert(work.get_one());
    }
    for(int i = 100; i < 200; ++i)
        results.erase(i);
    assert(results.empty());


}

BOOST_AUTO_TEST_CASE(test_CheckQueue_All)
{

    auto nThreads = 3;
    for (int i=0; i<nThreads-1; ++i)
        threadGroup.create_thread([=](){queue.Thread(nThreads);});
    n = 0;

    BOOST_TEST_MESSAGE("N was"<< n);
    {
        CCheckQueueControl<decltype(queue)> control(&queue, nThreads);

        std::vector<Dummy> vChecks;
        vChecks.reserve(100);
        for (int j = 0; j< 100; ++j)
        {
            for (int i=0; i<100; ++i)
                vChecks.push_back(Dummy{});
            control.Add(vChecks);
            vChecks.clear();
        }
    }
    BOOST_TEST_MESSAGE("N was"<< n);
    assert(n == 100*100);
}

BOOST_AUTO_TEST_SUITE_END()
