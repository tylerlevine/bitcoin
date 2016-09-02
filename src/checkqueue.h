// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <sstream>
#include <iostream>
#include <mutex>


/** These will produce compiler warnings if these types are
 * not guaranteed to be lock free on the platform */
#ifndef ATOMIC_BOOL_LOCK_FREE
#pragma message("std::atomic<bool> is not lock free")
#endif
#ifndef ATOMIC_LONG_LOCK_FREE
#pragma message("std::atomic<uint32_t> is not lock free")
#endif
#ifndef ATOMIC_LLONG_LOCK_FREE
#pragma message("std::atomic<uint64_t> is not lock free")
#endif


/** Forward Declaration on CCheckQueue. Note default no testing. */
template <typename T, bool TFE = false, bool TLE = false>
class CCheckQueue;
/** Forward Declaration on CCheckQueueControl */
template <typename Q, bool TFE = false, bool TLE = false>
class CCheckQueueControl;


/** CCheckQueue_Internals contains various components that otherwise could live inside
 * of CCheckQueue, but is separate for easier testability and modularity */
namespace CCheckQueue_Internals
{
/** check_storarge holds the atomic flags and the check data for the queue
     * and provides methods to assist in accessing or adding checks.
     */
template <typename T>
class check_storarge
{
    /** Vector to store raw checks */
    std::vector<T> checks;
    /** atomic flags which are used to mark a check as reserved from checks
             * C++11 standard guarantees that these are atomic  lock free on all platforms
             * 
             * Note: we wrap them with the default_cleared_flag to allow for them to be 
             * run-time initialized once. However, it is not safe to, say, copy a vector of such flags.*/
    struct default_cleared_flag : std::atomic_flag {
        default_cleared_flag() : std::atomic_flag() { clear(); };
        default_cleared_flag(const default_cleared_flag& s) : std::atomic_flag() { clear(); };
    };
    std::vector<default_cleared_flag> flags;
    /** The number of workers that was started with, eg, RunTime Number ScriptCheck Threads  */
    size_t RT_N_SCRIPTCHECK_THREADS;

public:
    /** Default constructor. init must be called with the right number of threads before use */
    check_storarge() : RT_N_SCRIPTCHECK_THREADS(0)
    {
    }
    /** Initializes the checks and flags. Should not be called during normal operation */
    void init(const size_t MAX_CHECKS, const size_t rt)
    {
        RT_N_SCRIPTCHECK_THREADS = rt;
        checks.reserve(MAX_CHECKS);
        flags.resize(MAX_CHECKS);
    }
    /** in place constructs a check. Caller must guarantee that this does not allocate
     * (if it does allocate, the check will not have an associated flag)
     */
    template< class... Args >
    void emplace_back(Args&& ... args)
    {
        checks.emplace_back(std::forward<Args>(args) ...);
    }

    /** Not thread safe method of determining the number of checks added */
    size_t size()
    {
        return checks.size();
    }

    /** reserve tries to set a flag for an element 
             * and returns if it was set by this thread */
    bool reserve(const size_t i)
    {
        return !flags[i].test_and_set();
    }

    /** Given a thread ID and an size, resets the flags that were supposed
     * to be controlled by that thread. */
    void reset_flags_for(const size_t ID, const size_t to)
    {
        for (size_t i = ID; i < to; i += RT_N_SCRIPTCHECK_THREADS)
            flags[i].clear();
    }
    /** eval runs a check at specified index */
    bool eval(const size_t i)
    {
        return checks[i]();
    }

    /** Clears the checks vector. Not thread safe, requires external synchronization.
     * Calls destructor of every check in the vector, freeing any associated memory (as long
     * as the check type T does not leak...) */
    void clear_check_memory()
    {
        checks.clear();
    }

    /** Testing functions... */
    decltype(&checks) TEST_get_checks()
    {
        return &checks;
    }
};

/** barrier is used to count the number of threads who are at a certain point within a round.  */
class barrier
{
    /** The number of workers that was started with, eg, RunTime Number ScriptCheck Threads  */
    size_t RT_N_SCRIPTCHECK_THREADS;
    std::atomic<size_t> count;

public:
    /** Default state is false so that first round looks like no prior round*/
    barrier() : RT_N_SCRIPTCHECK_THREADS(0), count(0)
    {
    }
    void init(const size_t rt)
    {
        RT_N_SCRIPTCHECK_THREADS = rt;
    }
    void finished()
    {
        ++count;
    }
    void wait_all_finished() const
    {
        while (count != RT_N_SCRIPTCHECK_THREADS)
            ;
    }
    void reset()
    {
        count.store(0);
    }
    void wait_reset() const
    {
        while (count.load() != 0)
            ;
    }
};
/* PriorityWorkQueue exists to help threads select work 
     * to do in a cache friendly way. As long as all entries added are
     * popped it will be correct. Performance comes from intelligently
     * choosing the order. Future optimizations can come here by taking
     * a smarter set of hints about checks that are definitely completed.
     *
     *
     * Each thread has a unique id, and preferentially evaluates
     * checks in an index i such that  i == id (mod RT_N_SCRIPTCHECK_THREADS) in increasing
     * order.
     *
     * After id aligned work is finished, the thread walks sequentially
     * through its neighbors (id +1%RT_N_SCRIPTCHECK_THREADS, id+2% RT_N_SCRIPTCHECK_THREADS) to find work.
     *
     *
     */
class PriorityWorkQueue
{
    /** This contains the number of checks known to be done by a worker (not the id of the check) */
    std::vector<size_t> n_done;
    /** The Worker's ID */
    const size_t id;
    /** The number of workers that was started with, eg, RunTime Number ScriptCheck Threads  */
    const size_t RT_N_SCRIPTCHECK_THREADS;
    /** Stores the total inserted since the last reset (ignores pop) */
    size_t total;
    /** a cache of the last queue we were popping from, reset on adds and (circularly) incremented on pops 
             * Otherwise pops have an O(workers) term, this keeps pop amortized constant */
    size_t id2_cache;

public:
    PriorityWorkQueue(size_t id_, size_t RT_N_SCRIPTCHECK_THREADS_) : n_done(), id(id_), RT_N_SCRIPTCHECK_THREADS(RT_N_SCRIPTCHECK_THREADS_), total(0), id2_cache((id_ + 1) % RT_N_SCRIPTCHECK_THREADS)
    {
        n_done.resize(RT_N_SCRIPTCHECK_THREADS);
    };

    void reset()
    {
        for (auto& i : n_done)
            i = 0;
        total = 0;
        id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
    }

    /** adds entries for execution [total, n)
             * Places entries in the proper bucket
             * Resets the next thread to help (id2_cache) if work was added
             */
    void add(const size_t n)
    {
        if (n > total) {
            total = n;
            id2_cache = (id + 1) % RT_N_SCRIPTCHECK_THREADS;
        }
    }

    size_t get_total() const
    {
        return total;
    }


    /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially
             * (from the last one on that neighbors stack)
             */
    bool pop(size_t& val, const bool stealing)
    {
        // First try to read from our own queue
        val = (id + (n_done[id]) * RT_N_SCRIPTCHECK_THREADS);
        if (val < total) {
            ++n_done[id];
            return true;
        }
        if (!stealing)
            return false;
        // Iterate untill id2 wraps around to id -- then we must be empty
        for (; id2_cache != id; id2_cache = (id2_cache + 1) % RT_N_SCRIPTCHECK_THREADS) {
            val = (id2_cache + (n_done[id2_cache]) * RT_N_SCRIPTCHECK_THREADS);
            if (val < total) {
                ++n_done[id2_cache];
                return true;
            }
        }
        return false;
    }
};

/** atomic_condition is used to control threads sleep/alive status.
 *
 * it is important for atomic_condition to function correctly that
 * it is only called the exactly once per operation (e.g., two consecutive calls to 
 * sleep will overflow the  state counter)
 */
class atomic_condition
{
    std::atomic<uint8_t> state;

public:
    atomic_condition() : state(0){};
    void wakeup()
    {
        ++state;
    }
    void sleep()
    {
        --state;
    }
    void kill()
    {
        state.store(3);
    }
    void resurrect()
    {
        state.store(0);
    }
    /** A thread who calls wait returns in either an
     * awake or killed state:
     * An awake atomic_condition will return true.
     * A killed atomic_condition will return  with false. 
     * An asleep thread will wait in 1 us increments
     *
     * A resurrected thread is equivalent to an asleep alive thread.*/
    bool wait() const
    {
        for (;;) {
            switch (state.load()) {
            case 0:
                std::this_thread::sleep_for(std::chrono::microseconds(1));
                break;
            case 1:
                return true;
            default:
                return false;
            }
        }
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
 * as an N'th worker, until all checks are done.
 *
 * @tparam T the type of callable check object
 *
 * The other params are only for testing and are default false. They are templated
 * as to incur no run-time overhead:
 *
 * @tparam TFE enables Test Functions to be called (and return meaningful output)
 * @tparam TLE stores data in the queue local logs. This must be dumped or it will use a lot of memory potentially.
 */

template <typename T, bool TFE, bool TLE>
class CCheckQueue
{
public:
    typedef T CHECK_TYPE;
    static const bool TEST_FUNCTIONS_ENABLE = TFE;
    static const bool TEST_LOGGING_ENABLE = TLE;

private:
    /** CCheckQueue_Internals members. See namespace CCheckQueue_Internals for documentation */

    CCheckQueue_Internals::check_storarge<CHECK_TYPE> checks;

    CCheckQueue_Internals::atomic_condition sleeper;

    /** Used to indicate when all the work has been finished in a given round */
    CCheckQueue_Internals::barrier work;

    /** Used to indicate that cleanup tasks have finished in a given round */
    CCheckQueue_Internals::barrier cleanup;

    /** The number of workers that was started with, eg, RunTime Number ScriptCheck Threads  */
    size_t RT_N_SCRIPTCHECK_THREADS;

    /** The maximum number of checks */
    size_t MAX_CHECKS;

    /** The number of checks put into the queue, done or not
     * Technically, some memory fence could synchronize the checks.size()  making this atomic redundant
     * */
    std::atomic<size_t> nAvail;

    /** true if all checks were successful, false if any failure occurs */
    std::atomic<bool> fAllOk;

    /** true if the master has joined, false otherwise. A round may not terminate unless masterJoined */
    std::atomic<bool> masterJoined;

    /** vector of handles for worker threads */
    std::vector<std::thread> threads;

    /** protects queue control functionality to one controller at a time. Probably safe to remove given cs_main lock. */
    std::mutex control_mtx;

    /** state only for testing */
    mutable std::atomic<size_t> test_log_seq;
    mutable std::vector<std::unique_ptr<std::ostringstream> > test_log;


    /* The main logic of a checkqueue round 
     *
     * returns when the worker has either observed an error, or has seen the master join and
     * exhausted all checks.
     *
     * If an error-ing check is seen, it is reported via fAllOk.
     *
     * the atomic variables are read on each loop as they should only be expensive to 
     * read after a write, less frequent reading would be acceptable as well if this
     * assumption is false.
     *
     */
    void consume(CCheckQueue_Internals::PriorityWorkQueue& work_queue)
    {
        for (;;) {
            // Note: Must check masterJoined before nAvail, otherwise
            // {Thread A: nAvail.load();} {Thread B:nAvail++; masterJoined = true;} {Thread A: masterJoined.load()}
            bool stealing = masterJoined.load();
            work_queue.add(nAvail.load());
            size_t check_id;
            bool got_data = work_queue.pop(check_id, stealing);
            if (got_data && checks.reserve(check_id)) {
                if (!checks.eval(check_id)) {
                    fAllOk.store(false);
                    return;
                }
            } else if (stealing && !got_data)
                return;
        }
    }

    /** Once the master thread has added all checks it joins under this function to do work.
     *
     * While this logic is similar to the Loop logic, it is slightly different as it performs
     * no cleanup and signals the master's presence
     */
    bool Master()
    {
        // Master's ID is always 0
        const size_t ID = 0;
        // Static initialize the work_queue and reset on each round, saves an allocation
        static CCheckQueue_Internals::PriorityWorkQueue work_queue(ID, RT_N_SCRIPTCHECK_THREADS);
        work_queue.reset();
        masterJoined.store(true);
        TEST_log(ID, [](std::ostringstream& o) { o << "Master just set masterJoined\n"; });
        consume(work_queue);
        work.finished();
        work.wait_all_finished();
        TEST_log(ID, [](std::ostringstream& o) { o << "(Master) saw all threads finished\n"; });
        bool fRet = fAllOk.load();
        // We must sleep the threads before the master leaves
        sleeper.sleep();
        masterJoined.store(false);
        return fRet;
    }
    void Loop(const size_t ID)
    {
        CCheckQueue_Internals::PriorityWorkQueue work_queue(ID, RT_N_SCRIPTCHECK_THREADS);
        while (sleeper.wait()) {
            // When we enter the loop, the thread is awake.
            TEST_log(ID, [](std::ostringstream& o) {o << "Round starting\n"; });
            consume(work_queue);
            // master may not have joined (in the case where a check failed)
            // so this only spins here if the master has not yet joined, otherwise consume finished all
            while (!masterJoined.load())
                ;
            // Retain a cached copy of the nAvail max value for cleanup
            size_t prev_total = nAvail.load();
            TEST_log(ID, [&, this](std::ostringstream& o) {
                o << "saw up to " << prev_total << " master was "
                << masterJoined.load() << " nAvail " << nAvail.load() << '\n';
            });
            // Mark finished
            work.finished();
            // We wait until the master reports leaving explicitly, meaning
            // it is safe to perform cleanup tasks without corrupting memory
            while (masterJoined.load())
                ;
            TEST_log(ID, [](std::ostringstream& o) { o << "Saw master leave\n"; });
            // Per thread cleanup tasks
            checks.reset_flags_for(ID, prev_total);
            cleanup.finished();
            TEST_log(ID, [](std::ostringstream& o) { o << "Resetting nAvail and fAllOk\n"; });
            // We have every thread set this arbitrarily. Only one thread needs to set this, but
            // this means no thread has to wait for another to set this.
            nAvail.store(0);
            fAllOk.store(true);
            if (ID == 1) {
                // Reset master flags too
                checks.reset_flags_for(0, prev_total);
                // Perform any single threaded garbage collection tasks
                checks.clear_check_memory();
                // Make sure every thread finishes the cleanup before allowing the master back in
                cleanup.wait_all_finished();
                cleanup.reset();
                // Master cannot rejoin until this call
                work.reset();
            }
            work_queue.reset();
        }

        LogPrintf("CCheckQueue @%#010x Worker %q shutting down\n", this, ID);
    }

public:
    CCheckQueue() : checks(), sleeper(), work(), cleanup(), RT_N_SCRIPTCHECK_THREADS(0),
                    nAvail(0), fAllOk(true), masterJoined(false), test_log_seq(0) {}

    void init(const size_t MAX_CHECKS_, const size_t RT_N_SCRIPTCHECK_THREADS_)
    {
        std::lock_guard<std::mutex> l(control_mtx);
        MAX_CHECKS = MAX_CHECKS_;
        RT_N_SCRIPTCHECK_THREADS = RT_N_SCRIPTCHECK_THREADS_;
        for (auto i = 0; i < RT_N_SCRIPTCHECK_THREADS && TEST_LOGGING_ENABLE; ++i)
            test_log.push_back(std::unique_ptr<std::ostringstream>(new std::ostringstream()));
        work.init(RT_N_SCRIPTCHECK_THREADS);
        cleanup.init(RT_N_SCRIPTCHECK_THREADS - 1);
        checks.init(MAX_CHECKS, RT_N_SCRIPTCHECK_THREADS);
        sleeper.resurrect();
        for (size_t id = 1; id < RT_N_SCRIPTCHECK_THREADS; ++id) {
            std::thread t([=]() {Thread(id); });
            threads.push_back(std::move(t));
        }
    }
    //! Worker thread
    void Thread(size_t ID)
    {
        RenameThread("bitcoin-scriptcheck");
        LogPrintf("Starting CCheckQueue Worker %q on CCheckQueue %#010x\n", ID, this);
        Loop(ID);
    }

    //! Control Lock should be held by any user of this queue
    void ControlLock()
    {
        control_mtx.lock();
        sleeper.wakeup();
        work.wait_reset();
    }
    void ControlUnlock()
    {
        control_mtx.unlock();
    };

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait()
    {
        return Master();
    }

    //! RAII container for emplacing checks without copying
    struct emplacer {
        CCheckQueue_Internals::check_storarge<CHECK_TYPE>& j;
        std::atomic<size_t>& nAvail;
        emplacer(CCheckQueue_Internals::check_storarge<CHECK_TYPE>& j_, std::atomic<size_t>& nAvail_) : j(j_), nAvail(nAvail_) {}
        template< class... Args >
        void operator()(Args&& ... args)
        {
            j.emplace_back(std::forward<Args>(args) ...);
        }
        ~emplacer()
        {
            nAvail.store(j.size());
        }
    };

    emplacer get_emplacer()
    {
        return emplacer(checks, nAvail);
    }

    //! Performs a clean shutdown of the queue. Does not release checks vectors
    void quit()
    {
        std::lock_guard<std::mutex> l(control_mtx);
        sleeper.kill();
        for (auto& t : threads)
            t.join();
        threads.clear();
        checks.clear_check_memory();
    }

    ~CCheckQueue()
    {
        quit();
    }


    /** Various testing functionalities */

    void TEST_consume(const size_t ID)
    {
        CCheckQueue_Internals::PriorityWorkQueue work_queue(ID, RT_N_SCRIPTCHECK_THREADS);
        if (TEST_FUNCTIONS_ENABLE)
            consume(work_queue);
    }

    void TEST_set_masterJoined(const bool b)
    {
        if (TEST_FUNCTIONS_ENABLE)
            masterJoined.store(b);
    }

    size_t TEST_count_set_flags()
    {
        auto count = 0;
        for (auto t = 0; t < MAX_CHECKS && TEST_FUNCTIONS_ENABLE; ++t)
            count += checks.reserve(t) ? 0 : 1;
        return count;
    }

    void TEST_reset_all_flags()
    {
        for (auto t = 0; t < MAX_CHECKS && TEST_FUNCTIONS_ENABLE; ++t)
            checks.reset_flag(t);
    }

    template <typename Callable>
    void TEST_log(const size_t ID, Callable c) const
    {
        if (TEST_LOGGING_ENABLE) {
            *test_log[ID] << "[[" << test_log_seq++ << "]] ";
            c(*test_log[ID]);
        }
    }

    void TEST_dump_log() const
    {
        if (TEST_FUNCTIONS_ENABLE) {
            LogPrintf("\n#####################\n## Round Beginning ##\n#####################");
            for (auto& i : test_log)
                LogPrintf("\n------------------\n%s\n------------------\n\n", i->str());
        }
    }

    void TEST_erase_log() const
    {
        if (TEST_FUNCTIONS_ENABLE)
            for (auto& i : test_log) {
                i->str("");
                i->clear();
            }
    }

    CCheckQueue_Internals::check_storarge<CHECK_TYPE>* TEST_introspect_checks()
    {
        return TEST_FUNCTIONS_ENABLE ? &checks : nullptr;
    }
};

/** 
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T, bool TFE, bool TLE>
class CCheckQueueControl
{
private:
    CCheckQueue<T, TFE, TLE>* const pqueue;
    bool fDone;

public:
    CCheckQueueControl(CCheckQueue<T, TFE, TLE>* pqueueIn) : pqueue(pqueueIn), fDone(false)
    {
        if (pqueue)
            pqueue->ControlLock();
    }

    bool Wait()
    {
        if (!pqueue || fDone)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        pqueue->ControlUnlock();
        return fRet;
    }

    typename CCheckQueue<T, TFE, TLE>::emplacer get_emplacer()
    {
        return pqueue->get_emplacer();
    }

    operator bool()
    {
        return pqueue != nullptr;
    }

    ~CCheckQueueControl()
    {
        Wait();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
