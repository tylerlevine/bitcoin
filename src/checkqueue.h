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

    std::array<CCheckQueueWorker<T>, MAX_SCRIPTCHECK_THREADS> worker_local_state;
    //! The number of workers (including the master) that are idle.
    boost::lockfree::queue<T*> queue;

    //! The total number of workers (including the master).

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
    std::atomic_uint nTodo;
    std::vector<T*> to_free_list;
    std::vector<T*> reserved_pool;

    
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


    
    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false, size_t MAX_ID = 1)
    {
        static std::atomic_uint cum_t {0};
        
        std::ostringstream oss;
        oss << boost::this_thread::get_id();
        std::string threadid = oss.str();
        // fMaster is always at index 0, worker must always get a higher index!
        if (fMaster){
            LogPrint("threading", "Worker Thread %s\n", threadid);
        }
        else{
            LogPrint("threading", "Master Thread %s\n", threadid);
        }
        bool fOk = true;
        //std::vector<T>* queue = &worker_local_state[worker_index].queue;
        for(;;) {
            // logically, the do loop starts here
            // Idle until has some work
            if (fMaster) {
                while (queue.empty()){
                    if (nTodo == 0) {
                        bool fRet = fAllOk;
                        // reset the status for new work later
                        if (fMaster)
                            fAllOk = true;
                        // return the current status
                        return fRet;
                    }
                }
            } else {
                while (queue.empty()) {
                }
            }
            T * check;
            fOk = fAllOk;
            
            while (nTodo) {
                if (fOk) {
                    //auto t1 = GetTimeMicros();
                    //auto t2 = 0;
                    if (queue.pop(check))
                    {
                        //t2 = GetTimeMicros() -t1;
                        //cum_t += t2;
                        //LogPrint("threading", "Queue pop took %d  micros,  total: [%q]\n", t2, cum_t   );
                        fOk = check ? (*check)() : fOk;
                        --nTodo;
                    } else {
                        break;
                    }

                } else {
                    fAllOk = false;
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
    //! Create a new check queue -- should be impossible to ever have more than 25k
    CCheckQueue(unsigned int nBatchSizeIn) : fAllOk(true), nTodo(0),  queue(25000) {}

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
        //static uint64_t cum_t = 0;
        //auto t1 = GetTimeMicros();
        to_free_list.reserve(to_free_list.size() + vChecks.size());
        BOOST_FOREACH (T& check, vChecks) {
            T* new_mem;
            if (reserved_pool.empty()) 
                new_mem = new T();
            else {
                new_mem = reserved_pool.back();
                reserved_pool.pop_back();
            }
                
            to_free_list.push_back(new_mem); // make sure this will be collected
            check.swap(*new_mem); // TODO: is this correct?
            // Guarantee a push
            while(!queue.bounded_push(new_mem))
            {
            }
        }
        nTodo += vChecks.size();
        //auto t2 = GetTimeMicros() - t1;
        //cum_t += t2;
        //LogPrint("threading", "Add Call took %d  micros,  total: [%q]\n", t2, cum_t   );
    }

    ~CCheckQueue()
    {
        unsafe_remove_worker_local_state();
    }
    void unsafe_remove_worker_local_state() {
        // This is very fast now (before was slow)
        //static int x = 0;
        //LogPrint("threading", "Deleting the free list\n");
        //auto t1 = GetTimeMicros();
        reserved_pool.insert(reserved_pool.end(), to_free_list.begin(), to_free_list.end());
        to_free_list.clear();
        //auto t2 = GetTimeMicros() - t1;
        //x += t2;
        //LogPrint("threading", "Finished deleting the free list, %d, total:[%d] \n", t3, x);
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
