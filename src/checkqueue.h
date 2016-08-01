// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>
#include "utiltime.h"
#include "random.h"
#include "util.h"

#include <boost/thread.hpp>
#include <mutex>

#include <atomic>
// This should be ignored eventually, but needs testing to ensure this works on more platforms
static_assert(ATOMIC_BOOL_LOCK_FREE, "shared_status not lock free");
static_assert(ATOMIC_LONG_LOCK_FREE, "shared_status not lock free");
static_assert(ATOMIC_LLONG_LOCK_FREE, "shared_status not lock free");
#include <sstream>
#include <string>
#include <queue>
#ifdef BOOST_THREAD_PLATFORM_PTHREAD
#include <pthread.h>
#include <thread>
#endif
static std::atomic<size_t> order_prints(0);


//#define logf(format, ...) LogPrintf("[[%q]]" format, ++order_prints, ##__VA_ARGS__)
#define logf(format, ...) 

/** cache_optimize is used to pad sizeof(type) to fit a cache line to limit contention.
 *
 * This is currently architecture dependent if the cache line sizes are correct.
 * Apparently true cache line sizes can only be determined at runtime. Wrong
 * size won't affect correctness, only performance.
 */
template <typename T, int cache_line = 64>
struct alignas(cache_line*((sizeof(T) + cache_line - 1) / cache_line)) cache_optimize : T {
};

/** clog2 determines at compile-time how many bits are needed to represent a field in a struct bitfield.
 *
 * For example, clog2(31) == 5, clog2(32) == 6.
 *
 * @param MAX the largest value stored.
 * @return the number of bits needed to store such an integer.
 */
constexpr size_t clog2(size_t MAX)
{
    return (MAX << 1) >> 1 == MAX ? clog2(MAX << 1) - 1 : 8 * sizeof(size_t);
}
static_assert(clog2(31) == 5, "clog2 is broken");
static_assert(clog2(32) == 6, "clog2 is broken");

namespace CCheckQueue_Helpers
{
/** job_array holds the atomic flags and the job data for the queue
 * and provides methods to assist in accessing or adding jobs.
 */
template <typename Q>
class job_array
{
    /** the raw check type */
    std::array<typename Q::JOB_TYPE, Q::MAX_JOBS> checks;
    /** atomic flags which are used to reserve a check from data 
     * C++11 guarantees that these are atomic
     * */
    std::array<cache_optimize<std::atomic_flag>, Q::MAX_JOBS> flags;
    std::array<std::function<void()>, Q::MAX_JOBS> cleanups;
    /** used as the insertion point into the array. */
    typename decltype(checks)::iterator next_free_index;

public:
    using queue_type = Q;
    /** add swaps a vector of checks into the checks array and increments the pointed 
     * only safe to run on master */
    job_array()
    {
        for (auto& i : cleanups)
            i = []() {};
        for (auto& i : flags)
            i.clear();
        next_free_index = checks.begin();
    }
    void add(std::vector<typename Q::JOB_TYPE>& vChecks)
    {
        for (typename Q::JOB_TYPE& check : vChecks)
            check.swap(*(next_free_index++));
    }

    /** reserve tries to set a flag for an element with memory_order_relaxed as we use other atomics for memory consistency
     * and returns if it was successful */
    bool reserve(size_t i)
    {
        return !flags[i].test_and_set();
    }

    /** reset_flag resets a flag with memory_order_relaxed, as we use other atomics for memory consistency*/
    void reset_flag(size_t i)
    {
        flags[i].clear();
    };

    /** eval runs a check at specified index */
    bool eval(size_t i)
    {
        return checks[i](cleanups[i]);
    };

    /** reset_jobs resets the insertion index only, so should only be run on master.
     *
     * NOTE: We have this cleanup done "for free"
     *      - data[i] is destructed by master on swap
     *      - flags[i] is reset by each thread while waiting to be cleared for duty
     */
    void reset_jobs()
    {
        next_free_index = checks.begin();
    };
    void job_cleanup(size_t upto)
    {
        for (int i = 0; i < upto; ++i) {
            cleanups[i]();
            cleanups[i] = []() {};
        }
    };
};
/* round_barrier is used to communicate that a thread has finished
 * all work and reported any bad checks it might have seen.
 *
 * Results should normally be cached thread locally.
 */

template <typename Q>
class round_barrier
{
    std::array<std::atomic_bool, Q::MAX_WORKERS> state;
    /** We pass a cache to round_barrier calls to decrease
      un-needed atomic-loads. Note that Cache is a reference. 
      Cache must be correct, it would unsafe to manually update cache. */

public:
    using Cache = std::array<bool, Q::MAX_WORKERS>;
    /** Default state is true so that first round looks like a previous round succeeded*/
    round_barrier()
    {
        for (auto& i : state)
            i = true;
    }

    void mark_done(size_t id, Cache& cache)
    {
        state[id] = true;
        cache[id] = true;
    };

    void mark_done(size_t id)
    {
        state[id] = true;
    };

    /** Iterates from [0,upto) to fetch status updates on unfinished workers.
     *
     * @param upto 
     * @param cache
     * @returns if all entries up to upto were true*/
    bool load_done(size_t upto, Cache& cache)
    {
        bool x = true;
        for (auto i = 0; i < upto; i++) {
            if (!cache[i]) {
                cache[i] = state[i].load();
                x = x && cache[i];
            }
        }
        return x;
    };

    /** resets all the bools. Can be used to coordinate cleanup processes.
     *
     */
    void reset(size_t upto)
    {
        for (auto i = 0; i < upto; ++i)
            state[i] = false;
    }

    /** Perfroms a read of the state 
    */
    bool is_done(size_t i)
    {
        return state[i];
    }

    bool is_done(size_t i, Cache& cache)
    {
        if (cache[i])
            return true;
        else {
            cache[i] = state[i];
            return true;
        }
    }
};
/* PriorityWorkQueue exists to help threads select work 
 * to do in a cache friendly way.
 *
 * Each thread has a unique id, and preferentiall evaluates
 * jobs in an index i such that  i == id (mod RT_N_SCRIPTCHECK_THREADS) in increasing
 * order.
 *
 * After id aligned work is finished, the thread walks sequentially
 * through its neighbors (id +1%RT_N_SCRIPTCHECK_THREADS, id+2% RT_N_SCRIPTCHECK_THREADS) to find work.
 * The thread iterates backwards, which means that threads will meet
 * in the middle.
 *
 * TODO: optimizations
 *     - Abort (by clearing)
 *       remaining on backwards walk if one that is reserved
 *       already, because it means either the worker's stuff is done
 *       OR it already has 2 (or more) workers already who will finish it.
 *     - Use an interval set rather than a vector (maybe)
 *     - Select thread by most amount of work remaining 
 *       (requires coordination)
 *     - Preferentially help 0 (the master) as it joins last
 *
 *
 *
 */
template <typename Q>
class PriorityWorkQueue
{
    /** The Worker's ID */
    const size_t id;
    /** The number of workers that bitcoind started with, eg, RunTime Number ScriptCheck Threads  */
    const size_t RT_N_SCRIPTCHECK_THREADS;
    std::array<std::array<size_t, 1 + (Q::MAX_JOBS / Q::MAX_WORKERS)>, Q::MAX_WORKERS> available;
    /** The tops and bottoms track the egion that has been inserted into or completed */
    std::array<typename std::array<size_t, 1 + (Q::MAX_JOBS / Q::MAX_WORKERS)>::iterator, Q::MAX_WORKERS> tops;
    std::array<typename std::array<size_t, 1 + (Q::MAX_JOBS / Q::MAX_WORKERS)>::iterator, Q::MAX_WORKERS> bottoms;
    /** Stores the number of elements remaining */
    size_t size;
    /** Stores the total inserted, for cleanup */
    size_t total;
    size_t id2_cache;


public:
    using queue_type = Q;
    struct OUT_OF_WORK {
    };
    PriorityWorkQueue(size_t id_, size_t RT_N_SCRIPTCHECK_THREADS_) : id(id_), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_)
    {
        reset();
    };
    /** adds entries for execution [total, n)
     * Places entries in the proper bucket
     * Resets the next thread to help if work was added
     */
    void add(size_t n)
    {
        if (n > total) {
            size += n - total;
            // TODO: More neatly
            for (; total < n; ++total) {
                auto worker_select = total % RT_N_SCRIPTCHECK_THREADS;
                *tops[worker_select] = total;
                ++tops[worker_select];
            }
        }
        id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
    };
    /** Completely reset the state */
    void reset()
    {
        for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i) {
            tops[i] = available[i].begin();
            bottoms[i] = available[i].begin();
        }
        size = 0;
        total = 0;
        id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
    };
    /** as if all elements had been processed via pop */
    void erase()
    {
        for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
            if (i == id)
                bottoms[i] = tops[i];
            else
                tops[i] = bottoms[i];
        size = 0;
        id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
    };

    /** accesses the highest id added, needed for external cleanup operations */
    size_t get_total()
    {
        return total;
    };


    /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially (from the last one)
    */
    size_t pop()
    {
        if (bottoms[id] < tops[id]) {
            --size;
            // post-fix so that we take bottom at current position
            return *(bottoms[id]++);
        }

        // Iterate untill id2 wraps around to id.
        for (; id2_cache != id; id2_cache = (id2_cache + 1) % RT_N_SCRIPTCHECK_THREADS) {
            // if the iterators aren't equal, then there is something to be taken from the top
            if (bottoms[id2_cache] == tops[id2_cache])
                continue;
            --size;
            // pre-fix so that we take top at position one back
            return *(--tops[id2_cache]);
        }

        // This should be checked by caller or caught
        throw OUT_OF_WORK{};
    };


    bool empty()
    {
        return size == 0;
    }
};

template <typename T, size_t s>
struct fake_array {
    T elt;
    T operator[](size_t ignore) 
    {
        return elt;
    };
};
template <typename Q>
struct status_container {
    /**Need clog2(MAX_JOBS +1) bits to represent 0 jobs and MAX_JOBS jobs, which should be around 17 bits */
    static_assert(clog2(Q::MAX_JOBS + 1) <= 64, "can't store that many jobs");
    std::atomic<size_t> nTodo;
    /** true if all checks were successful, false if any failure occurs */
    std::array<std::atomic<bool>, Q::MAX_WORKERS> fAllOk;
    /** true if the master has joined, false otherwise. A round may not terminate unless masterJoined */
    //std::array<std::atomic<bool>, Q::MAX_WORKERS> masterJoined;
    std::atomic<bool> masterJoined;
    /** used to signal external quit, eg, from ShutDown() */
    std::array<std::atomic<bool>, Q::MAX_WORKERS> fQuit;

    status_container()
    {
        for (auto i = 0; i < Q::MAX_WORKERS; ++i) {
            fAllOk[i].store(true);
            fQuit[i].store(false);
        }
            nTodo.store(0);
            masterJoined.store(false);
    }
    /** Force a store of the status to the initialized state */
    void reset(size_t id)
    {
        fAllOk[id].store(true);
        //nTodo[id].store(0);
    };
};
}


/** Queue for verifications that have to be performed.
 *
 * The verifications are represented by a type T, which must provide an
 * operator()(), returning a bool.
 *
 * One thread (the master) is assumed to push batches of verifications
 * onto the queue, where they are processed by N-1 worker threads. When
 * the master is done adding work, it temporarily joins the worker pool
 * as an N'th worker, until all jobs are done.
 *
 * @tparam T the type of callable check object
 * @tparam J the maximum number of jobs possible 
 * @tparam W the maximum number of workers possible
 */
template <typename T, size_t J, size_t W>
class CCheckQueue
{
public:
    using JOB_TYPE = T;
    static const size_t MAX_JOBS = J;
    static const size_t MAX_WORKERS = W;
    // We use the Proto version so that we can pass it to job_array, status_container, etc
    struct Proto {
        using JOB_TYPE = T;
        static const size_t MAX_JOBS = J;
        static const size_t MAX_WORKERS = W;
    };

private:
    CCheckQueue_Helpers::job_array<Proto> jobs;
    CCheckQueue_Helpers::status_container<Proto> status;
    CCheckQueue_Helpers::round_barrier<Proto> done_round;
    /** used to assign ids to threads initially */
    std::atomic_uint ids;
    /** used to count how many threads have finished cleanup operations */
    std::atomic_uint nFinishedCleanup;
    std::atomic<bool> masterMayEnter;
    void wait_all_finished_cleanup(size_t RT_N_SCRIPTCHECK_THREADS) const
    {
        while (nFinishedCleanup.load() != RT_N_SCRIPTCHECK_THREADS)
            ;//boost::this_thread::yield();
    }

    /** Internal function that does bulk of the verification work. */
    bool Loop(const bool fMaster, const size_t RT_N_SCRIPTCHECK_THREADS)
    {
        // If we are at 1 then CheckQueue should be disabled
        // Keep master always at 0 id -- maybe we should manually assign id's rather than this way, but this works.
        size_t ID = fMaster ? 0 : ++ids;
        assert(RT_N_SCRIPTCHECK_THREADS != 1);
        assert(ID < RT_N_SCRIPTCHECK_THREADS); // "Got and invalid ID, wrong nScriptThread somewhere");
#ifdef BOOST_THREAD_PLATFORM_PTHREAD
        {
            unsigned num_cpus = std::thread::hardware_concurrency();
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(ID%num_cpus, &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        }
#endif

        CCheckQueue_Helpers::PriorityWorkQueue<Proto> work_queue(ID, RT_N_SCRIPTCHECK_THREADS);
        logf("[%q] Entered \n", ID);

        for (;;) {
            // Round setup done here
            bool fOk = true;

            size_t prev_total = work_queue.get_total();
            // Technically we could skip this on the first iteration, but not really worth it for added code
            // We prefer reset to allocating a new one to save allocation.
            // reset last because we need to reset our flags
            work_queue.reset();

            // Have ID == 1 perform cleanup as the "slave master slave" as ID == 1 is always there if multicore
            // This frees the master to return with the result before the cleanup occurs
            // And allows for the ID == 1 to do the master's cleanup for it
            // We can immediately begin cleanup because all threads waited for master to
            // exit on previous round and master waited for all workers.
            switch (ID) {
            case 0:
                // Our cleanup should be done by ID == 1
                // and we already waited for is_cleanup_done
                // Mark master present
                logf("Master Joining \n");

                //for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                    status.masterJoined.store(true);

                logf("Master Joined \n");
                break;
            case 1:

                // We reset all the flags we think we'll use (also warms cache)
                for (size_t i = 1; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                status.reset(ID);
                // Reset master flags too -- if ID == 0, it's not wrong just not needed
                logf("Resetting Master\n");
                for (size_t i = 0; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                status.reset(0);
                status.nTodo = 0;

                // Cleanup Tasks
                jobs.job_cleanup(prev_total);


                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of cleanup occuring after others are running in main section
                wait_all_finished_cleanup(RT_N_SCRIPTCHECK_THREADS);
                nFinishedCleanup = 2;

                // There is actually no other cleanup we can do without causing some bugs unfortunately (race condition
                // with external adding)
                // However, it was critical to have all flags reset before proceeding
                // TODO: refactor to have each thread set themselves as being reset (except for master)
                // and only proceed when all are false.

                //
                // We have all the threads wait on their done_round to be reset, so we
                // Release all the threads

                logf("Cleanup Complete \n");
                done_round.reset(RT_N_SCRIPTCHECK_THREADS);
                
                masterMayEnter.store(true);
                logf("Cleanup Completion Notified\n");
                break;
            default:
                // We reset all the flags we think we'll use (also warms cache)

                for (size_t i = ID; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);

                status.reset(ID);

                logf("[%q] Idle\n", ID);
                ++nFinishedCleanup;
                // Wait till the cleanup process marks us not-done
                while (done_round.is_done(ID))
                    ;//boost::this_thread::yield();
                logf("[%q] Not Idle\n", ID);
            }
            size_t nDone {0};
            size_t nNotDone {0};
            for (;;) {
                if (status.fQuit[ID].load()) {
                    logf("Stopping Worker %q\n", ID);
                    status.fAllOk[ID].store(false);
                    done_round.mark_done(ID);
                    return false;
                }
                // Note: Must check masterJoined before nTodo, otherwise 
                // {Thread A: nTodo.load();} {Thread B:nTodo++; masterJoined = true;} {Thread A: masterJoined.load()} 
                bool masterJoined = status.masterJoined.load();
                assert(fMaster ? masterJoined : true);
                size_t nTodo = status.nTodo.load();

                // Add the new work.
                work_queue.add(nTodo);
                // We break if masterJoined and there is no work left to do
                bool noWork = work_queue.empty();


                if (noWork && fMaster) {
                    // default-initialize, but put one entry to dismiss compiler warning
                    typename decltype(done_round)::Cache done_cache {false};
                    // If We're the master then no work will be added so reaching this point signals
                    // exit unconditionally.
                    // We return the current status. Cleanup is handled elsewhere (RAII-style controller)

                    // Hack to prevent master looking up itself at this point...
                    done_cache[0] = true;
                    while (!done_round.load_done(RT_N_SCRIPTCHECK_THREADS, done_cache))
                        ;//boost::this_thread::yield();
                    bool fRet = fOk && status.fAllOk[ID];
                    // Allow others to exit now
                    done_round.mark_done(0, done_cache);
                    logf("[%q] Out of Work, did %q, skipped %q, condsidered %q \n", ID, nDone, nNotDone, nDone+nNotDone);
                    // We can mark the master as having left, because all threads have finished
                    logf("Master Leaving \n");
                    //for (int i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                    status.masterJoined.store(false);
                    return fRet;
                } else if (noWork && masterJoined) {
                    // If the master has joined, we won't find more work later
                    // mark ourselves as completed
                    // Any error would have already been reported
                    //
                    done_round.mark_done(ID);
                    logf("[%q] Out of Work, did %q, skipped %q, condsidered %q \n", ID, nDone, nNotDone, nDone+nNotDone);

                    // We wait until the master reports leaving explicitly
                    while (status.masterJoined)
                        ;//boost::this_thread::yield();
                    break;
                } else {
                    fOk = status.fAllOk[ID]; // Read fOk here, not earlier as it may trigger a quit
                    bool fOk_cache = fOk;

                    // The try/catch gets rid of explicit bound checking
                        while (!work_queue.empty() && fOk) {
                            size_t i = work_queue.pop();
                            if (jobs.reserve(i)) {
                                fOk = jobs.eval(i);
                                ++nDone;
                            } else {
                                ++nNotDone;
                            }
                        }

                    // Immediately make a failure such that everyone quits on their next read if this thread discovered the failure.
                    if (!fOk) {
                        work_queue.erase();
                        if (fOk_cache)
                            for (int i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                                status.fAllOk[i].store(false);
                    }
                }
            }
        }
    }

public:
    //! Create a new check queue -- should be impossible to ever have more than 100k checks
    CCheckQueue() : ids(0), nFinishedCleanup(2), masterMayEnter(false)
    {
        // Initialize all the state
    }

    void reset_ids()
    {
        ids = 0;
    }
    void reset_masterMayEnter()
    {
        masterMayEnter = false;
    }


    void wait_for_cleanup(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        bool b = true;
        while (!masterMayEnter.compare_exchange_weak(b, false)) {
            b = true;
            //boost::this_thread::yield();
        }
    }
    void reset_jobs()
    {
        jobs.reset_jobs();
    };
    //! Worker thread
    void Thread(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        Loop(false, RT_N_SCRIPTCHECK_THREADS);
    }


    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        return Loop(true, RT_N_SCRIPTCHECK_THREADS);
    }

    //! Add a batch of checks to the queue
    void Add(std::vector<T>& vChecks, size_t RT_N_SCRIPTCHECK_THREADS)
    {
        jobs.add(vChecks);
        size_t vs = vChecks.size();
        // Technically this is over strict as we are the ONLY writer to nTodo,
        // we could get away with aborting if it fails because it would unconditionally
        // mean fAllOk was false, therefore we would abort anyways...
        // But again, failure case is not the hot-path
        //for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
        status.nTodo += vs;
    }

    ~CCheckQueue()
    {
        quit_queue();
    }
    void quit_queue()
    {
        for (auto i = 0; i < MAX_WORKERS; ++i)
            status.fQuit[i].store(true);
    }

    void reset_quit_queue()
    {
        for (auto i = 0; i < MAX_WORKERS; ++i)
            status.fQuit[i].store(false);
    }
};

/** 
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename Q>
class CCheckQueueControl
{
private:
    Q* pqueue;
    bool fDone;
    size_t RT_N_SCRIPTCHECK_THREADS;

public:
    CCheckQueueControl(Q* pqueueIn, size_t RT_N_SCRIPTCHECK_THREADS_) : pqueue(pqueueIn), fDone(false), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_)
    {
        // FIXME: We no longer really have a concept of an unused queue so ignore... but maybe this is needed?
        // passed queue is supposed to be unused, or NULL
        //if (pqueue != NULL) {
        //        bool isIdle = pqueue->IsIdle();
        //      assert(isIdle);
        // }
        if (pqueue) {
            assert(RT_N_SCRIPTCHECK_THREADS != 1);
            logf("[0] Master waiting for cleanup to finish\n");
            pqueue->wait_for_cleanup(RT_N_SCRIPTCHECK_THREADS);
            logf("[0] Master saw cleanup done\n");
            pqueue->reset_jobs();
        }
    }

    bool Wait()
    {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait(RT_N_SCRIPTCHECK_THREADS);
        fDone = true;
        return fRet;
    }


    void Add(std::vector<typename Q::JOB_TYPE>& vChecks)
    {
        if (pqueue != NULL)
            pqueue->Add(vChecks, RT_N_SCRIPTCHECK_THREADS);
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
