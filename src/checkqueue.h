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

template <typename T, int cache_line = 64>
struct alignas(cache_line*((sizeof(T) + cache_line)/cache_line)) padded : T 
{
};

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
        void reset() {
            while (next_free_index--) { // Must be post-fix
                flags[next_free_index].clear();
                data[next_free_index].~T(); // <- Is this one needed TODO:
            }
            next_free_index = 0;
        }
        
    };
    struct shared_status { // Should fit into ONE cache line
        uint nTodo : clog2(MAX_JOBS+1);
        //uint finished : clog2(MAX_SCRIPTCHECK_THREADS+1);
        bool fAllOk : 1;
        bool masterJoined : 1;
        bool fQuit : 1;
        ~shared_status() {};
    };

    class round_barrier {
        std::array<std::atomic_bool, MAX_SCRIPTCHECK_THREADS> state;
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
        void reset() {
            for (auto& t : state)
                t = false;
        }
    };
    class PriorityWorkQueue {

        // Load things that align with our thread id 
        // into the priority evaluation section
        // and load all others into the remaining checksTodo
        // TODO: No need to load these into an array... just mark the highest and stride it!
        // TODO: Separate people by thing :) 
        job_array& jobs;
        size_t MAX_ID;
        size_t id;
        size_t top;
        size_t bot;
        size_t bot_other;
        struct OUT_OF_WORK_ERROR{};
        std::vector<size_t> unfinished_friends;
        size_t current_friend;
        size_t size;
        std::mt19937& urng;
        std::array<std::vector<size_t>, MAX_WORKERS> remaining_work;
        std::array<size_t, MAX_WORKERS> remaining_work_bottom;
    public:
        PriorityWorkQueue(job_array& jobs, size_t id_, size_t MAX_ID_, std::mt19937& urng_ ) : jobs(jobs), id(id_), MAX_ID(MAX_ID_), urng(urng_){
            unfinished_friends.reserve(MAX_ID-1);
            for (int i = 0; i < MAX_ID; ++i)
                remaining_work[i].reserve(1+MAX_JOBS/MAX_ID);
            reset();
        };
        void add_up_to_excl(size_t n){
            // if (n > top) {
              //  top = n;
              //  bot_other = 0;
            //}
            for (; top < n; ++top)
                remaining_work[top % MAX_ID].push_back(top);
            size +=  top < n ? n - top : 0;
        };
        void reset() {
            unfinished_friends.clear();
            for (auto i = 0; i < MAX_ID; ++i)
                if (i != id) 
                    unfinished_friends.push_back(id);
            std::shuffle(unfinished_friends.begin(), unfinished_friends.end(), urng);
            top = 0;
            bot = id;
            bot_other = 0;

            size = 0;
            current_friend = (id + 1) % MAX_ID;
            for (int i = 0; i < MAX_ID; ++i)
                remaining_work[i].clear();
        };

        size_t get_one() {
           // bot += MAX_ID;
           // if (bot < top)
           //     return bot;
           // bot -= MAX_ID;
            
           // if (bot_other+bot+1 >= top)
           //     throw OUT_OF_WORK_ERROR{};
           //return (++bot_other)+bot;


            if (remaining_work[id].size()-remaining_work_bottom[id] == 0) {
                while (remaining_work[current_friend].size() - remaining_work_bottom[current_friend] == 0) {
                    if ((current_friend) == id) // We've looped around
                        throw OUT_OF_WORK_ERROR{};
                }

                auto s = remaining_work[current_friend].rbegin();
                size_t s_ = *s;
                ++remaining_work_bottom[current_friend];
                --size;
                return s_;
            } else {

                auto s = remaining_work[id].back();
                remaining_work[id].pop_back();
                --size;
                return s;
            }
           
        };

        bool try_do_one() {
            if (empty())
                return false;
            size_t i = get_one();
            return jobs.reserve(i) ? jobs.eval(i) : true;
        }
        bool empty() {
            //return (bot + MAX_ID) >= top && (bot+bot_other +1 ) >= top;; // TODO: 
            return size == 0;

        }

        //if (priority_empty) {
        // Shuffle to limit cache conflicts for the non-assigned being checked. (only shuffle if we run out of work)
        // TODO: Sort such that ones likely to be completed are near the end to minimize conflicts
        // TODO: Steal from Master preferentially because they are late to join
        // TODO: Disabled if the prioritySection insertion already causes enough entropy?
        //  std::shuffle(checksTodo.begin(), checksTodo.end(), urng); 
                        //}

    };
    
    job_array jobs;
    std::atomic<shared_status> status;
    round_barrier done_round;
    std::atomic_bool reset;
    std::atomic_bool idle_gate;
    // Used to signal Exit for program cleanup, initialized false.
    std::atomic_uint ids;
    unsigned int nBatchSize;
    std::atomic_uint nIdle;

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
    void status_reset() {
        shared_status s;
        s.nTodo = 0;
        //s.finished = 0;
        s.fAllOk = true;
        s.masterJoined = false;
        status.store(s);
    };

    
    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false, size_t MAX_ID = 1)
    {
        // This should be ignored eventually...
        static_assert(ATOMIC_LLONG_LOCK_FREE, "shared_status not lock free");
        // Keep master always at 0 id -- maybe we should manually assign id's rather than this way...
        // We give each node an allocated priority set of pointers to try first to promote everyone getting work contention free.
        std::random_device rng;
        std::mt19937 urng(rng());
        size_t ID = fMaster ? 0 : ++ids;
        assert(ID < MAX_ID);// "Got and invalid ID, wrong nScriptThread somewhere");
        PriorityWorkQueue work_queue(jobs, ID, MAX_ID, urng);

        for(;;) {
            shared_status status_cached;
            std::array<bool, MAX_SCRIPTCHECK_THREADS> done_cache = {false};
            bool fOk = true;
            // ROUND SETUP?
            // If we reach this point we're running in multicore mode (master returns directly otherwise) 
            // Have ID == 1 perform cleanup as the "slave master slave" as ID == 1 is always there if multicore
            work_queue.reset();
            if (ID == 1 || MAX_ID ==1) 
            {
                // Wait until all threads are either master or idle, otherwise resetting could prevent finishing
                // because of premature cleanup
                while (nIdle +2 != MAX_ID)
                    boost::this_thread::yield();
                // Clean
                done_round.reset();
                jobs.reset();
                status_reset();
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
            // Wait for the reset bool unless master or 1
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
                if (status_cached.fQuit) 
                    return false;
                work_queue.add_up_to_excl(status_cached.nTodo); // Add the new work.
                // We break if masterJoined and there is no work left to do
                bool noWork =  work_queue.empty();
                assert(fMaster ? fMaster == status_cached.masterJoined : true); //, "Master failed to denote presence");

                if (noWork && fMaster) 
                {

                    // If We're the master then no work will be added so reaching this point signals
                    // exit unconditionally. 
                    // If fQuit, we should quit even if we are a worker.
                    // return the current status. Cleanup is handled elsewhere (RAII-style controller)
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

                    done_round.mark_done(ID, done_cache);
                    while (!done_round.load_done(MAX_ID, done_cache)) // We're waiting for the master to terminate at this point or for other threads to report errors.
                        boost::this_thread::yield();
                    break;
                } 
                else {

                    fOk = status_cached.fAllOk; // Read fOk here, not earlier as it may trigger a quit

                    while (!work_queue.empty() && fOk) 
                        fOk = work_queue.try_do_one();

                    // Immediately make a failure such that everyone quits on their next read.
                    if (!fOk)
                        status_cached = update([](shared_status s){
                                // Technically we're ok invalidating this so we should allow it to be (invalidated), which
                                // would let us just do an atomic store instead. (TODO: Prove this!)
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
        done_round.reset();
        status_reset();
        jobs.reset();
    }

    //! Worker thread
    void Thread()
    {
        Loop();
    }

    void Thread(size_t s)
    {
        Loop(false, s);
    }



    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait(size_t s)
    {
        update([](shared_status s) {
                s.masterJoined = true;
                return s;
        });
        return Loop(true, s);
    }

    //! Add a batch of checks to the queue
    void Add(std::vector<T>& vChecks)
    {
        jobs.add(vChecks);
        size_t vs = vChecks.size();
        // Technically this is over strict as we are the ONLY writer to nTodo,
        // we could get away with aborting if it fails because it would unconditionally
        // mean fAllOk was false, therefore we would abort anyways...
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
