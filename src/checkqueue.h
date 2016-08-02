// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>
#include "util.h"
#include <boost/thread.hpp>
#include <atomic>
// This should be ignored eventually, but needs testing to ensure this works on more platforms
static_assert(ATOMIC_BOOL_LOCK_FREE, "shared_status not lock free");
static_assert(ATOMIC_LONG_LOCK_FREE, "shared_status not lock free");
static_assert(ATOMIC_LLONG_LOCK_FREE, "shared_status not lock free");



/** CCheckQueue_Internals contains various components that otherwise could live inside
 * of CCheckQueue, but is separate for easier testability and modularity */
namespace CCheckQueue_Internals
{
/** job_array holds the atomic flags and the job data for the queue
 * and provides methods to assist in accessing or adding jobs.
 */
template <typename Q>
class job_array
{
    /** the raw check type */
    std::array<typename Q::JOB_TYPE, Q::MAX_JOBS> checks;
    /** atomic flags which are used to reserve a check from checks
     * C++11 standard guarantees that these are atomic on all platforms
     * */
    std::array<std::atomic_flag, Q::MAX_JOBS> flags;
    /** used as the insertion point into the array. */
    typename decltype(checks)::iterator next_free_index;

public:
    job_array()
    {
        for (auto& i : flags)
            i.clear();
        next_free_index = checks.begin();
    }
    /** add swaps a vector of checks into the checks array and increments the pointer
     * not threadsafe */
    void add(std::vector<typename Q::JOB_TYPE>& vChecks)
    {
        for (typename Q::JOB_TYPE& check : vChecks)
            check.swap(*(next_free_index++));
    }

    /** reserve tries to set a flag for an element 
     * and returns if it was successful */
    bool reserve(size_t i)
    {
        return !flags[i].test_and_set();
    }

    /** reset_flag resets a flag */
    void reset_flag(size_t i)
    {
        flags[i].clear();
    };

    /** eval runs a check at specified index */
    bool eval(size_t i)
    {
        return checks[i]();
    };

    /** reset_jobs resets the insertion index only, so should only be run on master.
     *
     * The caller must ensure that forall i, checks[i] is destructed and flags[i] is
     * reset.
     *
     * NOTE: This cleanup done "for free" elsewhere
     *      - checksi] is destructed by master on swap
     *      - flags[i] is reset by each thread while waiting to be cleared for duty
     */
    void reset_jobs()
    {
        next_free_index = checks.begin();
    };

};
/* round_barrier is used to communicate that a thread has finished
 * all work and reported any bad checks it might have seen.
 *
 * Results should normally be cached thread locally (once a thread is done, it
 * will not mark itself un-done so no need to read the atomic twice)
 */

template <typename Q>
class round_barrier
{
    std::array<std::atomic_bool, Q::MAX_WORKERS> state;

public:
    /** Default state is true so that first round looks like a previous round succeeded*/
    round_barrier()
    {
        for (auto& i : state)
            i = true;
    }

    void mark_done(size_t id)
    {
        state[id] = true;
    };

    /** Iterates from [0,upto) to fetch status updates on unfinished workers.
     *
     * @param upto 
     * @returns if all entries up to upto were true*/
    bool load_done(size_t upto)
    {
        bool x = true;
        for (auto i = 0; i < upto; i++) {
            x = x && state[i].load();
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

};
/* PriorityWorkQueue exists to help threads select work 
 * to do in a cache friendly way. As long as all entries added are
 * popped it will be correct. Performance comes from intelligently
 * chosing the order.
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
 * TODO: future optimizations
 *     - Abort (by clearing)
 *       remaining on backwards walk if one that is reserved
 *       already, because it means either the worker's stuff is done
 *       OR it already has 2 (or more) workers already who will finish it.
 *     - Use an interval set rather than a vector (maybe)
 *     - Select thread by most amount of work remaining 
 *       (requires coordination)
 *     - Preferentially help 0 (the master) as it joins last
 *     - have two levels of empty, priority_empty and all_empty
 *       (check for more work when priority_empty)
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
    /** Stores the number of elements remaining (ie, --size on pop)*/
    size_t size;
    /** Stores the total inserted since the last reset (ignores pop) */
    size_t total;
    /** a cache of the last queue we were popping from, reset on adds and (circularly) incremented on pops 
     * Otherwise pops have an O(workers) term, this keeps pop amortized constant */
    size_t id2_cache;


public:
    struct OUT_OF_WORK {
    };
    PriorityWorkQueue(size_t id_, size_t RT_N_SCRIPTCHECK_THREADS_) : id(id_), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_)
    {
        reset();
    };
    /** adds entries for execution [total, n)
     * Places entries in the proper bucket
     * Resets the next thread to help (id2_cache) if work was added
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


    /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially
     * (from the last one on that neighbors stack)
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

/** status_container stores the 
 * shared state for all nodes
 *
 * TODO: cache align things.*/
template <typename Q>
struct status_container {
    /** nTodo and  materJoined can be packed into one struct if desired*/
    std::atomic<size_t> nTodo;
    /** true if all checks were successful, false if any failure occurs */
    std::atomic<bool> fAllOk;
    /** true if the master has joined, false otherwise. A round may not terminate unless masterJoined */
    //std::array<std::atomic<bool>, Q::MAX_WORKERS> masterJoined;
    std::atomic<bool> masterJoined;
    /** used to signal external quit, eg, from ShutDown() */
    std::atomic<bool> fQuit;
    /** used to assign ids to threads initially */
    std::atomic_uint ids;
    /** used to count how many threads have finished cleanup operations */
    std::atomic_uint nFinishedCleanup;
    /** used to gate the creation of a CCheckQueueControl/master friom entering prematurely and signal when cleanup can occur */
    std::atomic<bool> masterMayEnter;
    /** used to signal when to go into low-cpu usage mode */
    std::atomic<bool> sleep;

    status_container() : nTodo(0), fAllOk(true), masterJoined(false), fQuit(false), ids(0), nFinishedCleanup(2), masterMayEnter(false), sleep(true) {}
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
    typedef T JOB_TYPE;
    static const size_t MAX_JOBS = J;
    static const size_t MAX_WORKERS = W;
    // We use the Proto version so that we can pass it to job_array, status_container, etc
    struct Proto {
        typedef T JOB_TYPE;
        static const size_t MAX_JOBS = J;
        static const size_t MAX_WORKERS = W;
    };

private:
    CCheckQueue_Internals::job_array<Proto> jobs;
    CCheckQueue_Internals::status_container<Proto> status;
    CCheckQueue_Internals::round_barrier<Proto> done_round;
    void wait_all_finished_cleanup(size_t RT_N_SCRIPTCHECK_THREADS) const
    {
        while (status.nFinishedCleanup.load() != RT_N_SCRIPTCHECK_THREADS)
            ;
        // could call boost::this_thread::yield() for better CPU utilization
        // This one shouldn't be that hot though
    }

    /** Internal function that does bulk of the verification work. */
    bool Loop(const bool fMaster, const size_t RT_N_SCRIPTCHECK_THREADS)
    {
        // If we are at 1 then CheckQueue should be disabled
        // Keep master always at 0 id -- maybe we should manually assign id's rather than this way, but this works.
        const size_t ID = fMaster ? 0 : ++status.ids;
        assert(RT_N_SCRIPTCHECK_THREADS != 1);
        assert(ID < RT_N_SCRIPTCHECK_THREADS); // "Got and invalid ID, wrong nScriptThread somewhere");

        CCheckQueue_Internals::PriorityWorkQueue<Proto> work_queue(ID, RT_N_SCRIPTCHECK_THREADS);

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

                //for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                status.masterJoined.store(true);

                break;
            case 1:

                // We reset all the flags we think we'll use (also warms cache)
                for (size_t i = 1; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                // Reset master flags too -- if ID == 0, it's not wrong just not needed
                for (size_t i = 0; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                status.nTodo.store(0);
                status.fAllOk.store(true);

                // TODO: Future Mutually Excluded Cleanup Tasks can go here

                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of cleanup occuring after others are running in main section
                wait_all_finished_cleanup(RT_N_SCRIPTCHECK_THREADS);
                status.nFinishedCleanup.store(2);

                // We have all the threads wait on their done_round to be reset, so we
                // Release all the threads
                done_round.reset(RT_N_SCRIPTCHECK_THREADS);
                status.masterMayEnter.store(true);

                break;
            default:
                // We reset all the flags we think we'll use (also warms cache)
                for (size_t i = ID; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                ++status.nFinishedCleanup;

                // Wait till the cleanup process marks us not-done
                // we could call boost::this_thread::yield() here, but this one is not too hot
                while (done_round.is_done(ID))
                    ;
            }
            while (!fMaster && status.sleep.load()) {

                if (status.fQuit.load()) {
                    LogPrintf("Stopping CCheckQueue Worker %q\n", ID);
                    status.fAllOk.store(false);
                    done_round.mark_done(ID);
                    return false;
                }
                boost::this_thread::yield();

            }
            for (;;) {
                if (status.fQuit.load()) {
                    LogPrintf("Stopping CCheckQueue Worker %q\n", ID);
                    status.fAllOk.store(false);
                    done_round.mark_done(ID);
                    return false;
                }
                // Note: Must check masterJoined before nTodo, otherwise
                // {Thread A: nTodo.load();} {Thread B:nTodo++; masterJoined = true;} {Thread A: masterJoined.load()}
                bool masterJoined = status.masterJoined.load();
                assert(fMaster ? masterJoined : true);
                size_t nTodo = status.nTodo.load();

                // TODO: A yield+continue could be put here if nTodo does not increase from the last round and not masterJoined

                // Add the new work to the queue.
                work_queue.add(nTodo);
                // We break if masterJoined and there is no work left to do
                bool noWork = work_queue.empty();


                if (noWork && fMaster) {
                    // If We're the master then no work will be added so reaching this point signals
                    // exit unconditionally.
                    

                    // Wait until all threads finish reporting errors. Otherwise we may miss
                    // an error
                    done_round.mark_done(0);
                    while (!done_round.load_done(RT_N_SCRIPTCHECK_THREADS))
                        ; //boost::this_thread::yield();

                    // We return the current status.
                    bool fRet = fOk && status.fAllOk;

                    status.sleep.store(true);
                    // Allow workers to exit now
                    // We can mark the master as having left, because all threads have finished
                    // and are not waiting on the masterJoined signal
                    status.masterJoined.store(false);
                    return fRet;
                } else if (noWork && masterJoined) {
                    // If the master has joined, we won't find more work later
                    // mark ourselves as completed
                    // Any error would have already been reported
                    //
                    done_round.mark_done(ID);

                    // We wait until the master reports leaving explicitly
                    // a boost::this_thread::yield() could be called here, but this while isn't particularly hot
                    while (status.masterJoined)
                        ;
                    break;
                } else {
                    fOk = status.fAllOk;
                    bool fOk_cache = fOk;

                    while (!work_queue.empty() && fOk) {
                        size_t i = work_queue.pop();
                        if (jobs.reserve(i))
                            fOk = jobs.eval(i);
                    }

                    // Immediately make a failure such that everyone quits on their next read if this thread discovered the failure.
                    // TODO: This code isn't very hot, but this could be made faster if the quitter tries to reserve all the jobs or
                    // something similar
                    if (!fOk) {
                        work_queue.erase();
                        if (fOk_cache)
                            status.fAllOk.store(false);
                    }
                }
            }
        }
    }

public:
    CCheckQueue() {}

    void reset_ids()
    {
        status.ids = 0;
    }
    void reset_masterMayEnter()
    {
        status.masterMayEnter = false;
    }
    void wait_for_cleanup(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        bool b = true;
        // we could call boost::this_thread::yield() in this loop, but this shouldn't be too hot because
        // cleanup should usually finish before master joins. Furthermore, we wouldn't want to
        // yield on a spurrious failure
        while (!status.masterMayEnter.compare_exchange_weak(b, false)) {
            b = true;
        }
    }
    void wakeup_workers() {
        status.sleep.store(false);
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
        status.nTodo += vs;
    }

    ~CCheckQueue()
    {
        quit_queue();
    }
    void quit_queue()
    {
        status.fQuit.store(true);
    }

    void reset_quit_queue()
    {
        status.fQuit.store(false);
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
        if (pqueue) {
            pqueue->wakeup_workers();
            assert(RT_N_SCRIPTCHECK_THREADS != 1);
            pqueue->wait_for_cleanup(RT_N_SCRIPTCHECK_THREADS);
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
