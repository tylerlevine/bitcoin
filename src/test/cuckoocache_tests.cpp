// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <boost/test/unit_test.hpp>
#include "cuckoocache.h"
#include "test/test_bitcoin.h"
#include "random.h"
#include <thread>
#include <boost/thread.hpp>


/** Test Suite for CuckooCache
 *
 *  1) All tests should have a deterministic result (using insecure rand
 *  with deterministic seeds)
 *  2) Some test methods are templated to allow for easier testing
 *  against new versions / comparing
 *  3) Results should be treated as a regression test, ie, did the behavior
 *  change significantly from what was expected. This can be OK, depending on
 *  the nature of the change, but requires updating the tests to reflect the new
 *  expected behavior. For example improving the hit rate may cause some tests
 *  using BOOST_CHECK_CLOSE to fail.
 *
 */

BOOST_AUTO_TEST_SUITE(cuckoocache_tests);
/** Arbitrarily selected Hit Rate threshold that happens to work for these tests
 * as a lower bound on performance. This can be changed (hopefully, to a higher
 * number) if the cache algorithm is further improved.
 */
double HitRateThresh = 0.8;


/** insecure_GetRandHash fills in a uint256 from insecure_rand
 */
void insecure_GetRandHash(uint256& t)
{
    uint32_t* ptr = (uint32_t*)t.begin();
    for (uint8_t j = 0; j < 8; ++j)
        *(ptr++) = insecure_rand();
}

/** Definition copied from /src/script/sigcache.cpp
 */
class uint256Hasher
{
public:
    template <uint8_t hash_select>
    uint32_t operator()(const uint256& key) const
    {
        static_assert(hash_select <8, "SignatureCacheHasher only has 8 hashes available.");
        uint32_t u;
        std::memcpy(&u, key.begin() + 4 * hash_select, 4);
        return u;
    }
};


/* Test that no values not inserted into the cache are read out of it.
 *
 * There are no repeats in the first 200000 insecure_GetRandHash calls
 */
BOOST_AUTO_TEST_CASE(test_cuckoocache_no_fakes)
{
    seed_insecure_rand(true);
    CuckooCache::cache<uint256, uint256Hasher> cc{};
    cc.setup_bytes(40 << 20);
    uint256 v;
    for (int x = 0; x < 100000; ++x) {
        insecure_GetRandHash(v);
        cc.insert(v);
    }
    for (int x = 0; x < 100000; ++x) {
        insecure_GetRandHash(v);
        BOOST_CHECK(!cc.contains(v, false));
    }
};

/** This helper returns the hit rate when megabytes*load worth of entries are
 * inserted into a megabytes sized cache
 */
template <typename Cache>
double test_cache(size_t megabytes, double load)
{
    seed_insecure_rand(true);
    std::vector<uint256> hashes;
    Cache set{};
    size_t bytes = megabytes * (1 << 20);
    set.setup_bytes(bytes);
    uint32_t n_insert = static_cast<uint32_t>(load * (bytes / sizeof(uint256)));
    hashes.resize(n_insert);
    for (uint32_t i = 0; i < n_insert; ++i) {
        uint32_t* ptr = (uint32_t*)hashes[i].begin();
        for (uint8_t j = 0; j < 8; ++j)
            *(ptr++) = insecure_rand();
    }
    /** We make a copy of the hashes because future optimizations of the
     * cuckoocache may overwrite the inserted element, so the test is
     * "future proofed".
     */
    std::vector<uint256> hashes_insert_copy = hashes;
    /** Do the insert */
    for (uint256& h : hashes_insert_copy)
        set.insert(h);
    /** Count the hits */
    uint32_t count = 0;
    for (uint256& h : hashes)
        count += set.contains(h, false);
    double hit_rate = ((double)count) / ((double)n_insert);
    return hit_rate;
}

/** The normalized hit rate for a given load.
 *
 * The semantics are a little confusing, so please see the below
 * explanation.
 *
 * Examples:
 *
 * 1) at load 0.5, we expect a perfect hit rate, so we multiply by
 * 1.0
 * 2) at load 2.0, we expect to see half the entries, so a perfect hit rate
 * would be 0.5. Therefore, if we see a hit rate of 0.4, 0.4*2.0 = 0.8 is the
 * normalized hit rate.
 *
 * This is basically the right semantics, but has a bit of a glitch depending on
 * how you measure around load 1.0 as after load 1.0 your normalized hit rate
 * becomes effectively perfect, ignoring freshness.
 */
double normalize_hit_rate(double hits, double load)
{
    return hits * std::max(load, 1.0);
}

/** Check the hit rate on loads ranging from 0.1 to 2.0 */
BOOST_AUTO_TEST_CASE(cuckoocache_hit_rate_ok)
{
    size_t megabytes = 40;
    for (double load = 0.1; load < 2; load *= 2) {
        double hits = test_cache<CuckooCache::cache<uint256, uint256Hasher>>(megabytes, load);
        BOOST_CHECK(normalize_hit_rate(hits, load) > HitRateThresh);
    }
}


/** This helper checks that erased elements are preferentially inserted onto and
 * that the hit rate of "fresher" keys is reasonable*/
template <typename Cache>
void test_cache_erase(size_t megabytes)
{
    double load = 1;
    seed_insecure_rand(true);
    std::vector<uint256> hashes;
    Cache set{};
    size_t bytes = megabytes * (1 << 20);
    set.setup_bytes(bytes);
    uint32_t n_insert = static_cast<uint32_t>(load * (bytes / sizeof(uint256)));
    hashes.resize(n_insert);
    for (uint32_t i = 0; i < n_insert; ++i) {
        uint32_t* ptr = (uint32_t*)hashes[i].begin();
        for (uint8_t j = 0; j < 8; ++j)
            *(ptr++) = insecure_rand();
    }
    /** We make a copy of the hashes because future optimizations of the
     * cuckoocache may overwrite the inserted element, so the test is
     * "future proofed".
     */
    std::vector<uint256> hashes_insert_copy = hashes;

    /** Insert the first half */
    for (uint32_t i = 0; i < (n_insert / 2); ++i)
        set.insert(hashes_insert_copy[i]);
    /** Erase the first quarter */
    for (uint32_t i = 0; i < (n_insert / 4); ++i)
        set.contains(hashes[i], true);
    /** Insert the second half */
    for (uint32_t i = (n_insert / 2); i < n_insert; ++i)
        set.insert(hashes_insert_copy[i]);

    /** elements that we marked erased but that are still there */
    size_t count_erased_but_contained = 0;
    /** elements that we did not erase but are older */
    size_t count_stale = 0;
    /** elements that were most recently inserted */
    size_t count_fresh = 0;

    for (uint32_t i = 0; i < (n_insert / 4); ++i)
        count_erased_but_contained += set.contains(hashes[i], false);
    for (uint32_t i = (n_insert / 4); i < (n_insert / 2); ++i)
        count_stale += set.contains(hashes[i], false);
    for (uint32_t i = (n_insert / 2); i < n_insert; ++i)
        count_fresh += set.contains(hashes[i], false);

    double hit_rate_erased_but_contained = ((double)count_erased_but_contained) / ((double)n_insert);
    double hit_rate_stale = ((double)count_stale) / ((double)n_insert);
    double hit_rate_fresh = ((double)count_fresh) / ((double)n_insert);

    /** As a whole on the load, we should be hitting around HitRateThresh.
    */

    BOOST_CHECK_CLOSE(hit_rate_fresh + hit_rate_erased_but_contained + hit_rate_stale, HitRateThresh, 10.0);

    /** On just the fresh things, we should be getting near perfect (mul by 2
     * because we divided by n_insert not n_insert/2).
     *
     * (We Check that our numbers are within 10.0% of perfect)
     */
    BOOST_CHECK_CLOSE(2 * hit_rate_fresh, 1.0, 10.0);
}

BOOST_AUTO_TEST_CASE(cuckoocache_erase_ok)
{
    size_t megabytes = 40;
    test_cache_erase<CuckooCache::cache<uint256, uint256Hasher>>(megabytes);
}

template <typename Cache>
void test_cache_erase_parallel(size_t megabytes)
{
    double load = 1;
    seed_insecure_rand(true);
    std::vector<uint256> hashes;
    Cache set{};
    size_t bytes = megabytes * (1 << 20);
    set.setup_bytes(bytes);
    uint32_t n_insert = static_cast<uint32_t>(load * (bytes / sizeof(uint256)));
    hashes.resize(n_insert);
    for (uint32_t i = 0; i < n_insert; ++i) {
        uint32_t* ptr = (uint32_t*)hashes[i].begin();
        for (uint8_t j = 0; j < 8; ++j)
            *(ptr++) = insecure_rand();
    }
    /** We make a copy of the hashes because future optimizations of the
     * cuckoocache may overwrite the inserted element, so the test is
     * "future proofed".
     */
    std::vector<uint256> hashes_insert_copy = hashes;
    boost::shared_mutex mtx;

    {
        /** Grab lock to make sure we release inserts */
        boost::unique_lock<boost::shared_mutex> l(mtx);
        /** Insert the first half */
        for (uint32_t i = 0; i < (n_insert / 2); ++i)
            set.insert(hashes_insert_copy[i]);
    }

    /** Spin up 3 threads to run contains with erase.
     */
    std::vector<std::thread> threads;
    /** Erase the first quarter */
    for (uint32_t x = 0; x < 3; ++x)
        /** Each thread is emplaced with x copy-by-value
        */
        threads.emplace_back([&, x] {
            boost::shared_lock<boost::shared_mutex> l(mtx);
            size_t ntodo = (n_insert/4)/3;
            size_t start = ntodo*x;
            size_t end = ntodo*(x+1);
            for (uint32_t i = start; i < end; ++i)
                set.contains(hashes[i], true);
        });

    /** Wait for all threads to finish
     */
    for (std::thread& t : threads)
        t.join();
    /** Grab lock to make sure we observe erases */
    boost::unique_lock<boost::shared_mutex> l(mtx);
    /** Insert the second half */
    for (uint32_t i = (n_insert / 2); i < n_insert; ++i)
        set.insert(hashes_insert_copy[i]);

    /** elements that we marked erased but that are still there */
    size_t count_erased_but_contained = 0;
    /** elements that we did not erase but are older */
    size_t count_stale = 0;
    /** elements that were most recently inserted */
    size_t count_fresh = 0;

    for (uint32_t i = 0; i < (n_insert / 4); ++i)
        count_erased_but_contained += set.contains(hashes[i], false);
    for (uint32_t i = (n_insert / 4); i < (n_insert / 2); ++i)
        count_stale += set.contains(hashes[i], false);
    for (uint32_t i = (n_insert / 2); i < n_insert; ++i)
        count_fresh += set.contains(hashes[i], false);

    double hit_rate_erased_but_contained = ((double)count_erased_but_contained) / ((double)n_insert);
    double hit_rate_stale = ((double)count_stale) / ((double)n_insert);
    double hit_rate_fresh = ((double)count_fresh) / ((double)n_insert);

    /** As a whole on the load, we should be hitting around HitRateThresh.
    */
    BOOST_CHECK_CLOSE(hit_rate_fresh + hit_rate_erased_but_contained + hit_rate_stale, HitRateThresh, 10.0);
    /** On just the fresh things, we should be getting near perfect (mul by 2
     * because we divided by n_insert not n_insert/2).
     *
     * (We Check that our numbers are within 10.0% of perfect)
     */
    BOOST_CHECK_CLOSE(2 * hit_rate_fresh, 1.0, 10.0);
}
BOOST_AUTO_TEST_CASE(cuckoocache_erase_parallel_ok)
{
    size_t megabytes = 40;
    test_cache_erase_parallel<CuckooCache::cache<uint256, uint256Hasher>>(megabytes);
}



template <typename Cache>
void test_cache_generations()
{
    seed_insecure_rand(true);
    struct activity {
        std::vector<uint256> reads;
        activity(uint32_t n_insert, Cache& c) : reads() {
            std::vector<uint256> inserts;
            inserts.resize(n_insert);
            reads.reserve(n_insert/2);
            for (uint32_t i = 0; i < n_insert; ++i) {
                uint32_t* ptr = (uint32_t*)inserts[i].begin();
                for (uint8_t j = 0; j < 8; ++j)
                    *(ptr++) = insecure_rand();
            }
            for (uint32_t i = 0; i < n_insert/4; ++i)
                reads.push_back(inserts[i]);
            for (uint32_t i = n_insert - (n_insert/4); i < n_insert; ++i)
                reads.push_back(inserts[i]);
            for (auto h : inserts)
                c.insert(h);
        }
    };

    const uint32_t BLOCK_SIZE = 10000;
    // 35 was experimentally picked for these parameters
    const uint32_t WINDOW_SIZE = 35;
    const uint32_t POP_AMOUNT = (BLOCK_SIZE/WINDOW_SIZE)/2;
    const double load = 10;
    const size_t megabytes = 40;
    const size_t bytes = megabytes * (1 << 20);
    const uint32_t n_insert = static_cast<uint32_t>(load * (bytes / sizeof(uint256)));

    std::vector<activity> hashes;
    Cache set{};
    set.setup_bytes(bytes);
    hashes.reserve(n_insert/BLOCK_SIZE);
    std::deque<activity> last_few;
    uint32_t out_of_tight_tolerance = 0;
    uint32_t total = n_insert/BLOCK_SIZE;
    for (uint32_t i = 0; i < total; ++i) {
        if (last_few.size() == WINDOW_SIZE)
            last_few.pop_front();
        last_few.emplace_back(BLOCK_SIZE, set);
        uint32_t count = 0;
        for (auto& act : last_few)
            for (uint32_t k = 0; k < POP_AMOUNT; ++k) {
                count += set.contains(act.reads.back(), true);
                act.reads.pop_back();
            }
        double hit = (double(count))/(last_few.size() * POP_AMOUNT);
        // Loose Check that we're within 10% of perfect
        BOOST_CHECK_CLOSE(hit, 1.0, 10.0);
        // Tighter check of number of times we are more than a percent away.
        out_of_tight_tolerance += hit < 0.99;
        BOOST_TEST_MESSAGE(hit);
        BOOST_TEST_MESSAGE("Booted: " << double(set.counter_boot) / double(set.total_boot) << "   == " << set.counter_boot << "  / " <<set.total_boot);
    }
    // Check that being out of tolerance happens less than 1% of the time
    BOOST_CHECK(double(out_of_tight_tolerance)/double(total) < 0.01);
    BOOST_TEST_MESSAGE(double(out_of_tight_tolerance)/double(total));
}
BOOST_AUTO_TEST_CASE(cuckoocache_generations)
{
    fPrintToConsole = true;
    test_cache_generations<CuckooCache::cache<uint256, uint256Hasher>>();
}

BOOST_AUTO_TEST_SUITE_END();
