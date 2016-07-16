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
    std::atomic_int nIdle;
    std::atomic_uint approx_queue_size;
    boost::lockfree::queue<T*> queue;

    //! The total number of workers (including the master).
    std::atomic_int nTotal;

    //! The temporary evaluation result.
    std::atomic_bool fAllOk;

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */
    std::atomic_uint nTodo;
    std::vector<T*> to_free_list;



    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize;

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false)
    {
        std::ostringstream oss;
        oss << boost::this_thread::get_id();
        std::string threadid = oss.str();
        // fMaster is always at index 0, worker must always get a higher index!
        size_t worker_index;
        if (fMaster){
            worker_index = 0;
            ++nTotal;
            LogPrint("threading", "Worker Thread %s\n", threadid);
        }
        else{
            worker_index = ++nTotal;
            LogPrint("threading", "Master Thread %s\n", threadid);
        }
        bool fOk = true;
        //std::vector<T>* queue = &worker_local_state[worker_index].queue;
        for(;;) {
            // logically, the do loop starts here
            // Idle until has some work
            nIdle++;
            if (fMaster) {
                while (queue.empty()){
                    if (nTodo == 0) {
                        nTotal--; // Exit the worker pool
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
            nIdle--;
            // Decide how many work units to process now.
            // * Do not try to do everything at once, but aim for increasingly smaller batches so
            //   all workers finish approximately simultaneously.
            // * Try to account for idle jobs which will instantly start helping.
            // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
            T * check;
            fOk = fAllOk;
            while (nTodo) {
                if (fOk) {
                    if (queue.pop(check))
                    {
                        if (check) {
                            fOk = (*check) ();
                            --nTodo;
                        } else {
                            LogPrint("threading", "Error Got a nullptr check!\n");
                        }
                    }
                } else {
                    fAllOk = false;
                    break;
                }
            }
        }
    }

public:
    //! Create a new check queue
    CCheckQueue(unsigned int nBatchSizeIn) : nIdle(0), nTotal(0), fAllOk(true), nTodo(0),  nBatchSize(nBatchSizeIn), queue(10000) {}

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
    uint64_t cum_t = 0;
    void Add(std::vector<T>& vChecks)
    {
        auto t1 = GetTimeMicros();
        to_free_list.reserve(to_free_list.size() + vChecks.size());
        BOOST_FOREACH (T& check, vChecks) {
            auto new_entry = new T();
            to_free_list.push_back(new_entry); // make sure this will be collected
            check.swap(*new_entry); // TODO: is this correct?
        // Guarantee a push
            while(!queue.push(new_entry))
            {
            }
        }
        nTodo += vChecks.size();
        approx_queue_size += vChecks.size();
        auto t2 = GetTimeMicros() - t1;
        cum_t += t2;
        LogPrint("threading", "Add Call took %d  micros,  %q total\n", t2, cum_t   );
    }

    ~CCheckQueue()
    {
    }
    void unsafe_remove_worker_local_state() {

        LogPrint("threading", "Deleting the free list\n");
        for (T* ptr : to_free_list) 
            delete ptr;
        to_free_list.clear();
        LogPrint("threading", "Finished deleting the free list\n");
    }

  //  bool IsIdle()
  //  {
  //      boost::unique_lock<boost::mutex> lock(mutex);
   //     return (nTotal == nIdle && nTodo == 0 && fAllOk == true);
    //}

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
