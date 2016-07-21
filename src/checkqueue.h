// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include "consensus/consensus.h"
#include <algorithm>
#include <vector>
#include "utiltime.h"
#include "random.h"

#include <boost/foreach.hpp>
#include <boost/thread.hpp>

#include <boost/thread/locks.hpp>
#include <boost/lockfree/queue.hpp>
#include <atomic>
#include <sstream>
#include <string>

template <typename T, size_t J, size_t W>
class CCheckQueueControl;


/** 
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */

// This is maybe not useful and architecture dependent
// It pads a sizeof(type) to fit a cache line
template <typename T, int cache_line = 64>
struct alignas(cache_line*((sizeof(T) + cache_line)/cache_line)) padded : T 
{
};

// Useful for determining how many bits are needed to represent a field
// in a struct bitfield
constexpr size_t clog2 (size_t x) {
    return (x << 1)>>1 == x ? clog2(x << 1) - 1 : 8*sizeof(size_t);
}

static_assert(clog2(31) == 5, "clog2 is broken");
static_assert(clog2(32) == 6, "clog2 is broken");

template <typename T, size_t J, size_t W>
class CCheckQueue
{
    using CHECK_TYPE = T;
    static const size_t MAX_JOBS = J;
    static const size_t MAX_WORKERS = W;
private:
    class job_array {
        std::array<T, MAX_JOBS> data;
        std::array<padded<std::atomic_flag>, MAX_JOBS> flags;
        size_t next_free_index = 0;
    public:
        void add (std::vector<T>& vChecks) {
            for (T& check : vChecks)
                check.swap(data[next_free_index++]);
        }
        bool reserve(size_t i) {
            return !flags[i].test_and_set(std::memory_order_acquire);

        }
        bool eval(size_t i) {
            return data[i]();
        }
        // FIXME: Need to mutually exclude any and all reset code
        // from the add code
        // Ideas: - get rid of reset by having add clear flags
        //        - Don't even need the destructor
        void reset() {
            while (next_free_index--) { // Must be post-fix
                flags[next_free_index].clear();
                data[next_free_index].~T(); // <- Is this one needed TODO:
            }
            next_free_index = 0;
        }
        
    };
    /* shared_status is used to communicate across threads critical state.
     * Should fit into ONE cache line/as small as possible so that it is 
     * lock-free atomic on many platforms. Even if it is not lock free
     * and requires locks, will still be correct.
     */
    struct shared_status { 
        // Should be around 17 bits
        // Need clog2(MAX_JOBS +1) bits to represent 0 jobs and MAX_JOBS jobs
        uint nTodo : clog2(MAX_JOBS+1); 
        bool fAllOk : 1;
        bool masterJoined : 1;
        bool fQuit : 1;
        ~shared_status() {};
    };
    /* round_barrier is used to communicate that a thread has finished
     * all work and reported any bad checks it might have seen.
     */
    class round_barrier {
        std::array<std::atomic_bool, MAX_SCRIPTCHECK_THREADS> state;
        // We pass a cache to round_barrier calls to decrease
        // un-needed atomic-loads. Note that Cache is a reference
        using Cache = std::array<bool, MAX_SCRIPTCHECK_THREADS>&;
    public:
        void mark_done(size_t id, Cache cache) {
            state[id] = true;
            cache[id] = true;
        };
        bool load_done(size_t upto, Cache cache) {
            bool x = true;
            for(auto i = 0;  i < upto; i++) {
                if (!cache[i])
                {
                    cache[i] = state[i].load();
                    x = x && cache[i];
                }
            }
            return x;

        };
        // TODO: Verify this claim
        // This mutually excludes any and all reset code
        // from the add code. 
        //
        // We can probably eliminate some other locking
        // by checking for when this resets
        void reset() {
            for (auto& t : state)
                t = false;
        }
    };
    /* PriorityWorkQueue exists to help threads select work 
     * to do in a cache friendly way.
     *
     * Each thread has a unique id, and preferentiall evaluates
     * jobs in an index i such that  i == id (mod MAX_ID) in increasing
     * order.
     *
     * After id aligned work is finished, the thread walks sequentially
     * through its neighbors (id +1%MAX_ID, id+2% MAX_ID) to find work.
     * The thread iterates backwards, which means that threads will meet
     * in the middle.
     *
     * TODO: optimizations
     *     - Abort (by clearing)
     *       remaining on backwards walk if one that is reserved
     *       already, because it means either the worker's stuff is done
     *       OR it already has 2 (or more) workers who will finish it.
     *     - Use an interval set rather than a vector (maybe)
     *     - Select thread by most amount of work remaining 
     *       (requires coordination)
     *     - Preferentially help 0 (the master) as it joins last
     *
     */
    class PriorityWorkQueue {
        job_array& jobs;
        size_t MAX_ID;
        size_t id;
        size_t top;
        struct OUT_OF_WORK_ERROR{};
        size_t currently_helping;
        size_t size;
        std::array<std::vector<size_t>, MAX_WORKERS> remaining_work;
        // This is used to emulate pop_front for a vector
        std::array<size_t, MAX_WORKERS> remaining_work_bottom;
    public:
        PriorityWorkQueue(job_array& jobs, size_t id_, size_t MAX_ID_) :
            jobs(jobs), id(id_), MAX_ID(MAX_ID_)
        {
            // We reserve on construction, one extra (potentially)
            for (int i = 0; i < MAX_ID; ++i)
                remaining_work[i].reserve(1+(MAX_JOBS/MAX_ID));
            reset();
        };
        // adds entries for execution up to, but not including, index n.
        // Places entries in the proper bucket
        void add_up_to_excl(size_t n){
            for (; top < n; ++top)
                remaining_work[top % MAX_ID].push_back(top);
            size +=  top < n ? n - top : 0;
        };
        // Completely reset the state
        void reset() {
            top = 0;
            size = 0;
            currently_helping = (id + 1) % MAX_ID;
            for (int i = 0; i < MAX_ID; ++i) {
                remaining_work[i].clear();
                remaining_work_bottom[i] = 0;
            }
        };

    
        /* Get one first from out own work stack (take the first one) and then try from neighbors sequentially (from the last one)
         */
        size_t get_one() {
            if ((remaining_work[id].size()-remaining_work_bottom[id]) == 0) {
                while ((remaining_work[currently_helping].size() - remaining_work_bottom[currently_helping]) == 0)
                {
                    if ((++currently_helping) == id) // We've looped around, and there's nothing
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

        // If we have work to do, do it.
        // If not, return true. 
        // This is safe because if it was already claimed then someone else
        // would report the error if it was a bad check
        bool try_do_one() {
            if (empty())
                return true;
            size_t i = get_one();
            return jobs.reserve(i) ? jobs.eval(i) : true;
        }
        bool empty() {
            return size == 0;
        }

    };
    
    /* 
     * Fields of the CCheckQueue 
     */
    job_array jobs;
    std::atomic<shared_status> status;
    round_barrier done_round;
    std::atomic_bool reset;
    std::atomic_bool idle_gate;
    // Used to signal Exit for program cleanup, initialized false.
    std::atomic_uint ids;
    unsigned int nBatchSize;
    std::atomic_uint nIdle;

    // Run a lambda update function until compexchg suceeds. Return modified copy for caching.
    template<typename Callable>
        shared_status update(Callable modify) {
            shared_status original;
            shared_status modified;
            do {
                original = status.load();
                modified = modify(original);
            } while ( ! status.compare_exchange_weak(original, modified));
            return modified;
        };
    // Force a store of the status to the cleaned state
    void status_reset() {
        shared_status s;
        s.nTodo = 0;
        s.fAllOk = true;
        s.masterJoined = false;
        status.store(s);
    };

    
    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false, size_t MAX_ID = 1)
    {
        // This should be ignored eventually, but needs testing to ensure this works on more platforms
        static_assert(ATOMIC_LLONG_LOCK_FREE, "shared_status not lock free");
        // Keep master always at 0 id -- maybe we should manually assign id's rather than this way, but this works.
        size_t ID = fMaster ? 0 : ++ids;
        assert(ID < MAX_ID);// "Got and invalid ID, wrong nScriptThread somewhere");
        PriorityWorkQueue work_queue(jobs, ID, MAX_ID);

        for(;;) {
            // Round setup done here
            shared_status status_cached;
            std::array<bool, MAX_SCRIPTCHECK_THREADS> done_cache = {false};
            bool fOk = true;
            // Technically we could skip this on the first iteration, but not really worth it for added code
            // We prefer reset to allocating a new one to save allocation.
            work_queue.reset();

            // Have ID == 1 perform cleanup as the "slave master slave" as ID == 1 is always there if multicore
            // This frees the master to return with the result before the cleanup occurs.
            if (ID == 1 || MAX_ID ==1) 
            {
                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of premature cleanup
                while (nIdle +2 != MAX_ID)
                    boost::this_thread::yield();
                // Clean
                jobs.reset();
                status_reset();
                // TODO: FIXME: We could just have all the threads wait on their done_round to be reset!
                done_round.reset();
                // Release all the threads
                //
                // This is a little odd. First, we close the idle gate such that all threads block at the reset waiting place
                // (we already know they are past here)
                //
                // Then, we open the reset gate, releasing all the threads.
                //
                idle_gate = false;
                reset = true;
            }
            // Wait for the reset bool unless master (0) or slave master slave (1)
            if ( ID > 1) {
                while (!idle_gate)
                    boost::this_thread::yield();
                ++nIdle;
                while (!reset)
                    boost::this_thread::yield();
                if(--nIdle == 0){ // Last one out closes the reset gate, and then opens the idle gate.
                    reset = false;
                    idle_gate = true;
                }
            }


            for (;;) {

                status_cached = status.load();
                // TODO: FIXME: This doesn't seem to actually quit the thread group
                if (status_cached.fQuit) 
                    return false;
                work_queue.add_up_to_excl(status_cached.nTodo); // Add the new work.
                // We break if masterJoined and there is no work left to do
                bool noWork =  work_queue.empty();
                assert(fMaster ? fMaster == status_cached.masterJoined : true); // Master failed to denote presence on join

                if (noWork && fMaster) 
                {

                    // If We're the master then no work will be added so reaching this point signals
                    // exit unconditionally. 
                    // We return the current status. Cleanup is handled elsewhere (RAII-style controller)
                    //
                    // Hack to prevent master looking up itself at this point...
                    done_cache[0] = true;

                    while (!done_round.load_done(MAX_ID, done_cache))
                        boost::this_thread::yield();
                    // Allow others to exit now.
                    status_cached = status.load(); 
                    bool fRet = status_cached.fAllOk;
                    done_round.mark_done(ID, done_cache);
                    return fRet;
                } 
                else if (noWork && status_cached.masterJoined)
                {
                    // If the master has joined, we won't find more work later

                    // mark ourselves as completed
                    done_round.mark_done(ID, done_cache);
                    // We're waiting for the master to terminate at this point
                    while (!done_round.load_done(MAX_ID, done_cache)) 
                        boost::this_thread::yield();
                    break;
                } 
                else {

                    fOk = status_cached.fAllOk; // Read fOk here, not earlier as it may trigger a quit

                    while (!work_queue.empty() && fOk) 
                        fOk = work_queue.try_do_one();

                    // Immediately make a failure such that everyone quits on their next read.
                    if (!fOk)
                        // Technically we're ok invalidating this so we should allow it to be (invalidated), which
                        // would let us just do an atomic store instead of updating. (TODO: Prove this!)
                        // Luckily, we aren't optimizing for failure case.
                        status_cached = update([](shared_status s){
                                s.fAllOk = false;
                                return s;
                                });
                }

            }

        }
    }

public:
    //! Create a new check queue -- should be impossible to ever have more than 100k checks
    CCheckQueue(unsigned int nBatchSizeIn) : reset(false), idle_gate(true), ids(0), nBatchSize(nBatchSizeIn) {
        // Initialize all the state
        status_reset();
        jobs.reset();
        done_round.reset();
    }

    //! Worker thread
    void Thread(size_t MAX_ID)
    {
        Loop(false, MAX_ID);
    }



    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait(size_t MAX_ID)
    {
        update([](shared_status s) {
                s.masterJoined = true;
                return s;
        });
        return Loop(true, MAX_ID);
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
    CCheckQueue<T,  J, W>* pqueue;
    bool fDone;
    size_t MAX_ID;
public:
    CCheckQueueControl(decltype(pqueue) pqueueIn, size_t MAX_ID_) : pqueue(pqueueIn), fDone(false), MAX_ID(MAX_ID_)
    {
        // FIXME: We no longer really have a concept of an unused queue so ignore... but maybe this is needed?

        // passed queue is supposed to be unused, or NULL
        //if (pqueue != NULL) {
        //        bool isIdle = pqueue->IsIdle();
        //      assert(isIdle);
        // }
    }

    bool Wait()
    {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait(MAX_ID);
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
