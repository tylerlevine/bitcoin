// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>
#include "util.h"
#include "utiltime.h"
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <sstream>
#include <iostream>
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

    decltype(&checks) TEST_get_checks() {
        return Q::TEST ? &checks : nullptr;

    }

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
    /** Default state is false so that first round looks like no prior round*/
    round_barrier()
    {
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

    /** resets one bool
     *
     */
    void reset(size_t i)
    {
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
    std::array<size_t, Q::MAX_WORKERS> n_done;
    /** Stores the number of elements remaining (ie, --size on pop)*/
    /** Stores the total inserted since the last reset (ignores pop) */
    size_t total;
    /** The Worker's ID */
    const size_t id;
    /** The number of workers that bitcoind started with, eg, RunTime Number ScriptCheck Threads  */
    const size_t RT_N_SCRIPTCHECK_THREADS;
    /** a cache of the last queue we were popping from, reset on adds and (circularly) incremented on pops 
     * Otherwise pops have an O(workers) term, this keeps pop amortized constant */
    size_t id2_cache;


public:
    struct OUT_OF_WORK {
    };
    PriorityWorkQueue() {};
    PriorityWorkQueue(size_t id_, size_t RT_N_SCRIPTCHECK_THREADS_) : n_done(), total(0), id(id_), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_), id2_cache((id_+1) % RT_N_SCRIPTCHECK_THREADS) {};
    /** adds entries for execution [total, n)
     * Places entries in the proper bucket
     * Resets the next thread to help (id2_cache) if work was added
     */
    void add(size_t n)
    {
        if (n > total) {
            total = n;
            id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
        }
    };
    size_t get_total()
    {
        return total;
    };


    /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially
     * (from the last one on that neighbors stack)
    */
    enum class popped_from : unsigned char {
        nowhere, self, other
    };
    bool pop(size_t& val, bool allow_stealing = true)
    {
        val = (id + (n_done[id]) * RT_N_SCRIPTCHECK_THREADS);
        if ( val < total) {
            ++n_done[id];
            return true;
        }

        // Iterate untill id2 wraps around to id.
        if (allow_stealing)
            for (; id2_cache != id; id2_cache = (id2_cache + 1) % RT_N_SCRIPTCHECK_THREADS) {
                // if the iterators aren't equal, then there is something to be taken from the top
                //
                val = (id2_cache + (n_done[id2_cache]) * RT_N_SCRIPTCHECK_THREADS);
                if ( val < total) {
                    ++n_done[id2_cache];
                    return true;
                }
            }


        return false;

    };

    void put_back_other(size_t val) {
        --n_done[val % RT_N_SCRIPTCHECK_THREADS];
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
    std::atomic<bool> masterJoined;
    /** used to count how many threads have finished cleanup operations */
    std::atomic_uint nFinishedCleanup;



    status_container() : nTodo(0), fAllOk(true), masterJoined(false), nFinishedCleanup(2) {
    }
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

enum testing_level : int {
    disabled = 0, enable_functions = 1, enable_logging = 2
};
constexpr testing_level operator&(testing_level a, testing_level b){
    return static_cast<testing_level>(static_cast<int>(a) & static_cast<int>(b));
}

constexpr testing_level operator|(testing_level a, testing_level b){
    return static_cast<testing_level>(static_cast<int>(a) | static_cast<int>(b));
}
template <typename T, size_t J, size_t W, testing_level TEST_ENABLE=testing_level::disabled>
class CCheckQueue;
template <typename T, size_t J, size_t W, testing_level TEST_ENABLE>
class CCheckQueue
{
public:
    typedef T JOB_TYPE;
    static const size_t MAX_JOBS = J;
    static const size_t MAX_WORKERS = W;
    static const testing_level TEST = TEST_ENABLE;
    // We use the Proto version so that we can pass it to job_array, status_container, etc

private:
    CCheckQueue_Internals::job_array<CCheckQueue<T, J, W, TEST>> jobs;
    CCheckQueue_Internals::status_container<CCheckQueue<T, J, W, TEST>> status;
    CCheckQueue_Internals::round_barrier<CCheckQueue<T, J, W, TEST>> done_round;
    std::array<std::ostringstream, MAX_WORKERS> test_log;
    bool init;
    std::atomic<bool> should_sleep;
    std::atomic_uint test_log_seq;



    void wait_all_finished_cleanup(size_t RT_N_SCRIPTCHECK_THREADS) const
    {
        while (status.nFinishedCleanup.load() != RT_N_SCRIPTCHECK_THREADS)
            ;
    }
    void maybe_sleep() {
        while (should_sleep)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    size_t consume(size_t ID, size_t RT_N_SCRIPTCHECK_THREADS) {

        if (TEST & testing_level::enable_logging)
            test_log[ID] << "[["<<++test_log_seq <<"]] " << "Worker ID [" << ID << "] in consume\n";
        CCheckQueue_Internals::PriorityWorkQueue<CCheckQueue<T, J, W, TEST>> work_queue(ID, RT_N_SCRIPTCHECK_THREADS);
        // Note: Must check masterJoined before nTodo, otherwise
        // {Thread A: nTodo.load();} {Thread B:nTodo++; masterJoined = true;} {Thread A: masterJoined.load()}
        size_t job_id = 0;
        while (status.fAllOk.load()) {
            bool allow_stealing = status.masterJoined.load();
            work_queue.add(status.nTodo.load());
            bool got_data = work_queue.pop(job_id, allow_stealing);
            // Immediately make a failure such that everyone quits on their next read of fOk
            got_data && jobs.reserve(job_id) && (jobs.eval(job_id) ||  (status.fAllOk.store(false), false));
            if ((TEST & testing_level::enable_logging) && got_data)
                test_log[ID] << "[["<<++test_log_seq <<"]] "<< "Job ID was " << job_id << '\n';
            if (allow_stealing && !got_data)
                break;
        }
        if (TEST & testing_level::enable_logging)
            test_log[ID] << "[["<<++test_log_seq <<"]] " << "Worker ID [" << ID << "] leaving consume. fAllOk was "<<status.fAllOk.load() <<"\n";
        return work_queue.get_total();
    }
    /** Internal function that does bulk of the verification work. */
    bool Loop(const size_t ID, const size_t RT_N_SCRIPTCHECK_THREADS)
    {


        for (;;) {
            if (ID != 0)
                maybe_sleep();

            if (TEST & testing_level::enable_logging)
                test_log[ID] << "[["<<++test_log_seq <<"]] " << "Worker ID [" << ID << "] starting\n";
            size_t prev_total = consume(ID, RT_N_SCRIPTCHECK_THREADS);
            if (TEST & testing_level::enable_logging)
                test_log[ID] << "[["<<++test_log_seq <<"]] "<< "Worker ID [" << ID << "] saw up to " <<prev_total << " master was "<< status.masterJoined.load() << " nTodo " << status.nTodo.load() << '\n';

            // We only break out of the loop when there is no more work and the master had joined.
            // We won't find more work later, so mark ourselves as completed
            // Any error would have already been reported
            if (!status.fAllOk.load())
                while (!status.masterJoined.load())
                    ;
            done_round.mark_done(ID);

            // If we are the master:
            //  1) Wait till all threads finish
            //  2) read fAllOk
            //  3) Mark master as gone
            //  4) return
            if (ID == 0) {
                while (!done_round.load_done(RT_N_SCRIPTCHECK_THREADS))
                    ;
                if (TEST & testing_level::enable_logging)
                    test_log[ID] << "[["<<++test_log_seq <<"]] "<< "Worker ID [" << ID << "] saw all threads finished\n";
                bool fRet = status.fAllOk;
                sleep();
                status.masterJoined.store(false);
                return fRet;
            } 

            // We wait until the master reports leaving explicitly
            while (status.masterJoined.load())
                ;
            if (TEST & testing_level::enable_logging)
                test_log[ID] << "[["<<++test_log_seq <<"]] "<< "Worker ID [" << ID << "] saw master leave\n";

            // Have ID == 1 perform cleanup as the "slave master slave" as ID == 1 is always there if multicore
            // This frees the master to return with the result before the cleanup occurs
            // And allows for the ID == 1 to do the master's cleanup for it
            // We can immediately begin cleanup because all threads waited for master to
            // exit on previous round and master waited for all workers.



            // We reset all the flags we think we'll use (also warms cache)
            for (size_t i = ID; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                jobs.reset_flag(i);
            if (ID == 1) {
                // Reset master flags too -- if ID == 0, it's not wrong just not needed
                for (size_t i = 0; i < prev_total; i += RT_N_SCRIPTCHECK_THREADS)
                    jobs.reset_flag(i);
                
                if (TEST & testing_level::enable_logging)
                    test_log[ID] << "[["<<++test_log_seq <<"]] "<< "Resetting nTodo" <<'\n';
                status.nTodo.store(0);
                status.fAllOk.store(true);

                // TODO: Future Mutually Excluded Cleanup Tasks can go here

                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of cleanup occuring after others are running in main section
                wait_all_finished_cleanup(RT_N_SCRIPTCHECK_THREADS);
                status.nFinishedCleanup.store(2);
                // We have all the threads wait on their done_round to be reset, so we
                // Release all the threads, master last
                for (auto i = 1; i < RT_N_SCRIPTCHECK_THREADS; ++i)
                    done_round.reset(i);
                done_round.reset(0);
            } else {
                ++status.nFinishedCleanup;
                work_queue.reset();
                while (done_round.is_done(ID))
                    ;
            }
        }
    }

public:
    CCheckQueue() : jobs(), status(), done_round(), init(false), should_sleep(true), test_log_seq(0) {
    }

    void wait_for_cleanup(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        while (done_round.is_done(0)) {
        }
        if (TEST & testing_level::enable_logging)
            test_log[0] << "[["<<++test_log_seq <<"]] "<< "Worker ID [" << 0 <<"] cleanup waiting done!\n";
    }
    void reset_jobs()
    {
        jobs.reset_jobs();
    };
    //! Worker thread
    void Thread(size_t ID, size_t RT_N_SCRIPTCHECK_THREADS)
    {
        RenameThread("bitcoin-scriptcheck");
        Loop(ID, RT_N_SCRIPTCHECK_THREADS);
    }


    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait(size_t RT_N_SCRIPTCHECK_THREADS)
    {
        status.masterJoined.store(true);
        if (TEST & testing_level::enable_logging)
            test_log[0] << "[["<<++test_log_seq <<"]] "<< "Master Just Set masterJoined\n";
        return Loop(0, RT_N_SCRIPTCHECK_THREADS);
    }

    //! Add a batch of checks to the queue
    void Add(std::vector<T>& vChecks, size_t RT_N_SCRIPTCHECK_THREADS)
    {
        jobs.add(vChecks);
        size_t vs = vChecks.size();
        status.nTodo.fetch_add(vs);
        if (TEST & testing_level::enable_logging)
            test_log[0] << "[["<<++test_log_seq <<"]] "<< "Added "<<vs<<" values. nTodo was "<< status.nTodo.load() - vs << " now is " << status.nTodo.load()  << " \n";
    }

    ~CCheckQueue()
    {
    }

    void thread_init(const size_t RT_N_SCRIPTCHECK_THREADS) {

        if (init)
            return;
        init = true;
        std::thread t([=](){Thread(1, RT_N_SCRIPTCHECK_THREADS); });
        std::swap(t, submaster);
    }
    void wakeup() {

        //for (auto& s : sleepers)
            //s.wakeup();
    }
    void sleep() {
        //for (auto& s : sleepers)
            //s.sleep();
    }

    size_t TEST_consume(size_t ID, size_t RT_N_SCRIPTCHECK_THREADS) {
        return TEST & testing_level::enable_functions ? consume(ID, RT_N_SCRIPTCHECK_THREADS) : 0;
    }
    void TEST_set_masterJoined(bool b) {
        if (TEST & testing_level::enable_functions)
            status.masterJoined.store(b);
    }

    size_t TEST_count_set_flags() {
        auto count = 0;
        if (TEST & testing_level::enable_functions)
            for (auto t = 0; t < MAX_JOBS; ++t)
                count += jobs.reserve(t) ? 0 : 1;
        return count;
    }
    void TEST_reset_all_flags() {
        if (TEST & testing_level::enable_functions)
            for (auto t = 0; t < MAX_JOBS; ++t)
                jobs.reset_flag(t);

    }
    void TEST_dump_log(size_t upto) {

        if (TEST & testing_level::enable_functions & testing_level::enable_logging)
            for (auto i = 0; i < upto; ++i)
                LogPrintf("\n------------------\n%s\n------------------\n\n", test_log[i].str());
    };

    void TEST_erase_log() {
        if (TEST & testing_level::enable_functions & testing_level::enable_logging)
            for (auto i = 0; i < MAX_WORKERS; ++i){
                test_log[i].str("");
                test_log[i].clear();
            }
    };
    decltype(&status) TEST_introspect_status() {
        return TEST & testing_level::enable_functions ? &status : nullptr;
    }
    decltype(&jobs) TEST_introspect_jobs() {
        return TEST & testing_level::enable_functions ? &jobs : nullptr;
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
            pqueue->wakeup();
            assert(RT_N_SCRIPTCHECK_THREADS != 1);
            // Only done once on the first creation
            pqueue->thread_init(RT_N_SCRIPTCHECK_THREADS);
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
