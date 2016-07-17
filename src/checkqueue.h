// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>
#include "utiltime.h"

#include <boost/foreach.hpp>
#include <boost/thread.hpp>

#include <boost/thread/locks.hpp>
#include <boost/lockfree/queue.hpp>
#include <atomic>

template <typename T>
class CCheckQueueControl;

enum class WorkerState : char {
    off, active, idle
};
template <typename T>
struct CCheckQueueWorker {
    std::atomic<WorkerState> status;
};

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
template <typename T>
class CCheckQueue
{
private:


    std::array<CCheckQueueWorker<T>, MAX_SCRIPTCHECK_THREADS> worker_local_state;
    //! The number of workers (including the master) that are idle.
    boost::lockfree::queue<T*> queue;

    //! The total number of workers (including the master).

    //! The temporary evaluation result.
    std::atomic_bool fAllOk;

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */
    std::atomic_uint nTodo;
    std::vector<T*> to_free_list;
    std::vector<T*> reserved_pool;




    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false)
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
            }
        }
    }

public:
    //! Create a new check queue -- should be impossible to ever have more than 25k
    CCheckQueue(unsigned int nBatchSizeIn) : fAllOk(true), nTodo(0),  queue(25000) {}

    //! Worker thread
    void Thread()
    {
        Loop();
    }

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait()
    {
        return Loop(true);
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
template <typename T>
class CCheckQueueControl
{
private:
    CCheckQueue<T>* pqueue;
    bool fDone;

public:
    CCheckQueueControl(CCheckQueue<T>* pqueueIn) : pqueue(pqueueIn), fDone(false)
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
        bool fRet = pqueue->Wait();
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
        pqueue->unsafe_remove_worker_local_state();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
