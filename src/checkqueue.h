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

template <typename T, size_t J, size_t W>
class CCheckQueueControl;



/** cache_optimize is used to pad sizeof(type) to fit a cache line to limit contention.
 *
 * This is currently architecture dependent if the cache line sizes are correct.
 * Apparently true cache line sizes can only be determined at runtime. Wrong
 * size won't affect correctness, only performance.
 */
template <typename T, int cache_line = 64>
struct alignas(cache_line*((sizeof(T) + cache_line) / cache_line)) cache_optimize : T {
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
    using CHECK_TYPE = T;
    static const size_t MAX_JOBS = J;
    static const size_t MAX_WORKERS = W;

private:
    /** job_array holds the atomic flags and the job data for the queue
     * and provides methods to assist in accessing or adding jobs.
     */
    class job_array
    {
        /** the raw check type */
        std::array<T, MAX_JOBS> checks;
        /** atomic flags which are used to reserve a check from data 
         * C++11 guarantees that these are atomic
         * */
        std::array<cache_optimize<std::atomic_flag>, MAX_JOBS> flags;
        std::array<std::function<void()>, MAX_JOBS> cleanups;
        /** used as the insertion point into the array. */
        size_t next_free_index = 0;

    public:
        /** add swaps a vector of checks into the checks array and increments the pointed 
         * only safe to run on master */
        job_array() 
        {
            for(auto& i : cleanups)
                i = [](){};
        }
        void add(std::vector<T>& vChecks)
        {
            for (T& check : vChecks)
                check.swap(checks[next_free_index++]);
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
            next_free_index = 0;
        };
        void job_cleanup(size_t upto)
        {
            for (int i = 0; i< upto; ++i) {
                cleanups[i]();
                cleanups[i] = [](){};
            }

        };
    };
    /* shared_status is used to communicate across threads critical state.
     * Should fit into ONE cache line/as small as possible so that it is 
     * lock-free atomic on many platforms. Even if it is not lock free
     * and requires locks, will still be correct.
     *
     * If fAllOk is false, all other fields may be invalidated.
     */
    struct shared_status {
        /**Need clog2(MAX_JOBS +1) bits to represent 0 jobs and MAX_JOBS jobs, which should be around 17 bits */
        uint nTodo : clog2(MAX_JOBS + 1);
        /** true if all checks were successful, false if any failure occurs */
        bool fAllOk : 1;
        /** true if the master has joined, false otherwise. A round may not terminate unless masterJoined */
        bool masterJoined : 1;
        /** used to signal external quit, eg, from ShutDown() */
        bool fQuit : 1;
    };
    /* round_barrier is used to communicate that a thread has finished
     * all work and reported any bad checks it might have seen.
     *
     * Results should normally be cached thread locally.
     */
    class round_barrier
    {
        std::array<std::atomic_bool, MAX_WORKERS> state;
        /** We pass a cache to round_barrier calls to decrease
        un-needed atomic-loads. Note that Cache is a reference. 
        Cache must be correct, it would unsafe to manually update cache. */
        using Cache = std::array<bool, MAX_WORKERS>&;

    public:
        /** Default state is true so that first round looks like a previous round succeeded*/
        round_barrier()
        {
            for (auto& i : state)
                i = true;
        }

        void mark_done(size_t id, Cache cache)
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
        bool load_done(size_t upto, Cache cache)
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
            for (auto i = 0; i< upto; ++i)
                state[i] = false;
        }

        /** Perfroms a read of the state freshly
         */
        bool is_done(size_t i)
        {
            return state[i];
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
    class PriorityWorkQueue
    {
        /** A reference to the pool's job_array */
        job_array& jobs;
        /** The Worker's ID */
        const size_t id;
        /** The number of workers that bitcoind started with, eg, RunTime Number ScriptCheck Threads  */
        const size_t RT_N_SCRIPTCHECK_THREADS;
        /** The highest index inserted so far */
        size_t top;
        /** the current number of elements remaining */
        size_t size;
        /** The other thread id to help*/
        size_t currently_helping;
        struct OUT_OF_WORK_ERROR {
        };
        /** We reserve space here for the remaining work only once
         * TODO: We can probably do this better at compile time with an array<bool>*/
        std::array<std::vector<size_t>, MAX_WORKERS> remaining_work;
        /** This is used to emulate pop_front for a vector */
        std::array<size_t, MAX_WORKERS> remaining_work_bottom;

    public:
        PriorityWorkQueue(job_array& jobs, size_t id_, size_t RT_N_SCRIPTCHECK_THREADS_) : jobs(jobs), id(id_), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_)
        {
            // We reserve on construction, one extra (potentially)
            for (int i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                remaining_work[i].reserve(1 + (MAX_JOBS / RT_N_SCRIPTCHECK_THREADS));
            reset();
        };
        /** adds entries for execution [top,n)
        * Places entries in the proper bucket
        * Resets the next thread to help if work was added
        */
        void add(size_t n)
        {
            for (; top < n; ++top)
                remaining_work[top % RT_N_SCRIPTCHECK_THREADS].push_back(top);
            size += top < n ? n - top : 0;
            currently_helping = top< n ? (id+1) % RT_N_SCRIPTCHECK_THREADS : currently_helping;
        };
        /** Completely reset the state */
        void reset()
        {
            top = 0;
            size = 0;
            currently_helping = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
            for (int i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i) {
                remaining_work[i].clear();
                remaining_work_bottom[i] = 0;
            }
        };

        /** accesses the highest id added, needed for external cleanup operations */
        size_t get_top()
        {
            return top;
        };


        /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially (from the last one)
         */
        size_t get_one()
        {
            if ((remaining_work[id].size() - remaining_work_bottom[id]) == 0) {
                while ((remaining_work[currently_helping].size() - remaining_work_bottom[currently_helping]) == 0) {
                    // We've looped around, and there's nothing on anyone's
                    if ((++currently_helping) == id) 
                        throw OUT_OF_WORK_ERROR{};
                }

                size_t s = remaining_work[currently_helping].back();
                remaining_work[id].pop_back();
                --size;
                return s;
            } else {
                size_t s = remaining_work[id].front();
                ++remaining_work_bottom[id];
                --size;
                return s;
            }
        };

        /** If we have work to do, do it.
        * If not, return true.
        * This is safe because if it was already claimed then someone else
        * would report the error if it was a bad check
        *
        * @returns true if no check failed (including if no checks were run), false otherwise 
        * 
        */
        bool try_do_one()
        {
            if (empty())
                return true;
            size_t i = get_one();
            return jobs.reserve(i) ? jobs.eval(i) : true;
        }

        bool empty()
        {
            return size == 0;
        }
    };

    /* 
     * instances of the nested classes of the CCheckQueue
     */
    job_array jobs;
    std::atomic<shared_status> status;

    round_barrier done_round;
    /** used to assign ids to threads initially */
    std::atomic_uint ids;
    /** used to count how many threads have finished cleanup operations */
    std::atomic_uint nIdle;
    std::mutex cleanup_mtx;


    /** Run a lambda update function until compexchg suceeds. Return modified copy for caching.
     *
     * lambda may run unlimited times so should be side effect free.
     */
    template <typename Callable>
    shared_status update(Callable modify)
    {
        shared_status original;
        shared_status modified;
        do {
            original = status.load();
            modified = modify(original);
        } while (!status.compare_exchange_weak(original, modified));
        return modified;
    };



    /** Internal function that does bulk of the verification work. */
    bool Loop(const bool fMaster, const size_t RT_N_SCRIPTCHECK_THREADS)
    {
        // If we are at 1 then CheckQueue should be disabled
        assert(RT_N_SCRIPTCHECK_THREADS != 1); 
        // Keep master always at 0 id -- maybe we should manually assign id's rather than this way, but this works.
        size_t ID = fMaster ? 0 : ++ids;
        assert(ID < RT_N_SCRIPTCHECK_THREADS); // "Got and invalid ID, wrong nScriptThread somewhere");
        PriorityWorkQueue work_queue(jobs, ID, RT_N_SCRIPTCHECK_THREADS);

        for (;;) {
            // Round setup done here
            shared_status status_cached;
            std::array<bool, MAX_WORKERS> done_cache = {false};
            bool fOk = true;

            size_t prev_top = work_queue.get_top();
            // Technically we could skip this on the first iteration, but not really worth it for added code
            // We prefer reset to allocating a new one to save allocation.
            // reset last because we need to reset our flags
            work_queue.reset();

            // Have ID == 1 perform cleanup as the "slave master slave" as ID == 1 is always there if multicore
            // This frees the master to return with the result before the cleanup occurs
            // And allows for the ID == 1 to do the master's cleanup for it
            if (ID == 1 ) {
                // We reset all the flags we think we'll use (also warms cache)
                for (int i = ID; i < prev_top; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                // Reset master flags too -- if ID == 0, it's not wrong just not needed
                for (int i = 0; i < prev_top; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);

                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of premature cleanup
                while (nIdle + 2 < RT_N_SCRIPTCHECK_THREADS)
                    boost::this_thread::yield();
                // Cleanup
                {
                    jobs.job_cleanup(prev_top);
                    cleanup_mtx.unlock();
                }


                // There is actually no other cleanup we can do without causing some bugs unfortunately (race condition
                // with external adding)
                // However, it was critical to have all flags reset before proceeding
                // TODO: refactor to have each thread set themselves as being reset (except for master) 
                // and only proceed when all are false.

                //
                // We have all the threads wait on their done_round to be reset, so we
                // Release all the threads
                done_round.reset(RT_N_SCRIPTCHECK_THREADS);
            }
            else if (ID == 0) {
                // Our cleanup should be done by ID == 1 but double check
                while (done_round.is_done(ID))
                    boost::this_thread::yield();
            }
            // Wait for the reset bool unless master (0) or slave master slave (1)
            else if (ID > 1) {
                ++nIdle;
                // We reset all the flags we think we'll use (also warms cache)
                for (int i = ID; i < prev_top; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                // Wait till the cleanup process marks us not-done
                while (done_round.is_done(ID))
                    boost::this_thread::yield();
                --nIdle;
            }


            for (;;) {
                status_cached = status.load();

                if (status_cached.fQuit) {
                    LogPrintf("Stopping Worker %q\n", ID);
                    return false;
                }

                // Add the new work.
                work_queue.add(status_cached.nTodo); 
                // We break if masterJoined and there is no work left to do
                bool noWork = work_queue.empty();
                // Master failed to denote presence on join
                assert(fMaster ? fMaster == status_cached.masterJoined : true);

                if (noWork && fMaster) {
                    // If We're the master then no work will be added so reaching this point signals
                    // exit unconditionally.
                    // We return the current status. Cleanup is handled elsewhere (RAII-style controller)

                    // Hack to prevent master looking up itself at this point...
                    done_cache[0] = true;

                    while (!done_round.load_done(RT_N_SCRIPTCHECK_THREADS, done_cache))
                        boost::this_thread::yield();
                    // Allow others to exit now
                    status_cached = status.load();
                    bool fRet = status_cached.fAllOk;
                    // Unfortunately, status must be reset here.
                    status_reset();
                    done_round.mark_done(ID, done_cache);
                    return fRet;
                } else if (noWork && status_cached.masterJoined) {
                    // If the master has joined, we won't find more work later

                    // mark ourselves as completed
                    done_round.mark_done(ID, done_cache);
                    // We're waiting for the master to terminate at this point
                    while (!done_round.load_done(RT_N_SCRIPTCHECK_THREADS, done_cache))
                        boost::this_thread::yield();
                    break;
                } else {
                    fOk = status_cached.fAllOk; // Read fOk here, not earlier as it may trigger a quit

                    while (!work_queue.empty() && fOk)
                        fOk = work_queue.try_do_one();

                    // Immediately make a failure such that everyone quits on their next read.
                    if (!fOk)
                        // Technically we're ok invalidating this so we should allow it to be (invalidated), which
                        // would let us just do an atomic store instead of updating. (TODO: Prove this!)
                        // Luckily, we aren't optimizing for failure case.
                        status_cached = update([](shared_status s) {
                                s.fAllOk = false;
                                return s;
                        });
                }
            }
        }
    }

public:
    //! Create a new check queue -- should be impossible to ever have more than 100k checks
    CCheckQueue() : ids(0)
    {
        // Initialize all the state
        cleanup_mtx.lock();
        status_reset();
    }

    void wait_until_clean() {
        cleanup_mtx.lock();
    }
    /** Force a store of the status to the initialized state */
    void status_reset()
    {
        shared_status s;
        s.nTodo = 0;
        s.fAllOk = true;
        s.masterJoined = false;
        s.fQuit = false;
        status.store(s);
    };

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
        update([](shared_status s) {
                s.masterJoined = true;
                return s;
        });
        return Loop(true, RT_N_SCRIPTCHECK_THREADS);
    }

    //! Add a batch of checks to the queue
    void Add(std::vector<T>& vChecks)
    {
        jobs.add(vChecks);
        size_t vs = vChecks.size();
        // Technically this is over strict as we are the ONLY writer to nTodo,
        // we could get away with aborting if it fails because it would unconditionally
        // mean fAllOk was false, therefore we would abort anyways...
        // But again, failure case is not the hot-path
        update([vs](shared_status s) {
                s.nTodo += vs;
                return s;
        });
    }

    ~CCheckQueue()
    {
        quit_queue();
    }
    void quit_queue()
    {
        shared_status s;
        s.fQuit = true;
        status.store(s);
    }
};

/** 
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T, size_t J, size_t W>
class CCheckQueueControl
{
private:
    CCheckQueue<T, J, W>* pqueue;
    bool fDone;
    size_t RT_N_SCRIPTCHECK_THREADS;

public:
    CCheckQueueControl(decltype(pqueue) pqueueIn, size_t RT_N_SCRIPTCHECK_THREADS_) : pqueue(pqueueIn), fDone(false), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_)
    {
        // FIXME: We no longer really have a concept of an unused queue so ignore... but maybe this is needed?

        // passed queue is supposed to be unused, or NULL
        //if (pqueue != NULL) {
        //        bool isIdle = pqueue->IsIdle();
        //      assert(isIdle);
        // }
        if (pqueue) {
            pqueue->wait_until_clean();
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

    void Add(std::vector<T>& vChecks)
    {
        if (pqueue != NULL)
            pqueue->Add(vChecks);
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
