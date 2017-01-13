// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>

#include <boost/foreach.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

template <typename T>
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
template <typename T>
class CCheckQueue
{
private:
    //! Mutex to ensure that sleeping threads are woken.
    boost::mutex mutex;

    //! Worker threads block on this when out of work
    boost::condition_variable condWorker;

    //! The temporary evaluation result.
    std::atomic<uint8_t> fAllOk;

    /**
     * Number of verification threads that aren't in stand-by. When a thread is
     * awake it may have a job that will return false, but is yet to report the
     * result through fAllOk.
     */
    std::atomic<unsigned int> nAwake;

    /** If there is presently a master process either in the queue or adding jobs */
    std::atomic<bool> fMasterPresent;

    //! Whether we're shutting down.
    bool fQuit;

    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize;

    //! A pointer to contiguous memory that contains all checks
    T* check_mem {nullptr};

    /** A bit-packed {uint32_t, uint32_t} representing the begin and end
     * pointers into check_mem. They are packed into one atomic so that they can
     * be atomically read and modified together.
     */
    std::atomic<uint64_t> check_mem_top_bot {0};

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false)
    {
        // jobs_left returns true if there is work to be done
        // it reads the latest version of the state without
        // updating v (enforced by compiler by scope order)
        auto jobs_left = [&]{
            uint64_t x = check_mem_top_bot;
            return ((uint32_t) (x >> 32)) > ((uint32_t) x);
        };

        // no_work_left returns true if there isn't work to be done
        // it reads the version of the state cached in v
        uint64_t v;
        auto no_work_left = [&]{
            return ((uint32_t) (v >> 32)) == ((uint32_t) v);
        };

        uint8_t fOk = 1;
        // first iteration, only count non-master threads
        if (!fMaster)
            ++nAwake;
        for (;;) {
            v = check_mem_top_bot;
            // Try to increment v by 1 if our version of v indicates that there
            // is work to be done.
            // E.g., if v = 10<<32 + 10, don't attempt to exchange.
            //       if v = 10<<32 + 9, then do attempt to exchange
            //
            // compare_exchange_weak, on failure, updates v to latest
            while (!no_work_left() &&
                    !check_mem_top_bot.compare_exchange_weak( v, v+1));
            // If our loop terminated because of no_work_left...
            if (no_work_left())
            {
                if (fMaster) {
                    // There's no harm to the master holding the lock
                    // at this point because all the jobs are taken.
                    // so busy spin until no one else is awake
                    while (nAwake) {}
                    bool fRet = fAllOk;
                    // reset the status for new work later
                    fAllOk = 1;
                    // return the current status
                    return fRet;
                } else {
                    --nAwake;
                    // Unfortunately we need this lock for this to be safe
                    // We hold it for the min time possible
                    {
                        if (!fMasterPresent) { // Read once outside the lock and once inside
                            boost::unique_lock<boost::mutex> lock(mutex);
                            if (!fMasterPresent) {
                                condWorker.wait(lock, jobs_left);
                            }
                        }
                    }
                    ++nAwake;
                }
            } else {
                // We compute using v (not v+1 as above) because it is 0-indexed
                T * pT = check_mem + ((uint32_t) v);
                // Check whether we need to do work at all (can be read outside
                // of lock because it's fine if a worker executes checks
                // anyways)
                fOk = fAllOk;
                // execute work
                fOk &= fOk && (*pT)();
                // We swap in a default constructed value onto pT before freeing
                // so that we don't accidentally double free when check_mem is
                // freed. We don't strictly need to free here, but it's good
                // practice in case T uses a lot of memory.
                auto t = T();
                pT->swap(t);
                // Can't reveal result until after swapped, otherwise
                // the master thread might exit and we'd double free pT
                fAllOk &= fOk;
            }
        }
    }

public:
    //! Mutex to ensure only one concurrent CCheckQueueControl
    boost::mutex ControlMutex;

    //! Create a new check queue
    CCheckQueue(unsigned int nBatchSizeIn) :  fAllOk(1), nAwake(0), fMasterPresent(false),  fQuit(false), nBatchSize(nBatchSizeIn), check_mem(nullptr), check_mem_top_bot(0) {}

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

    //! Setup is called once per batch to point the CheckQueue to the
    // checks & restart the counters.
    void Setup(T* check_mem_in)
    {
        check_mem = check_mem_in;
        check_mem_top_bot = 0;
        fMasterPresent = true;
        boost::unique_lock<boost::mutex> lock(mutex);
        condWorker.notify_all();
    }
    void Cleanup()
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        fMasterPresent = false;
    }

    //! Add a batch of checks to the queue
    void Add(size_t size)
    {
        check_mem_top_bot += size<<32;
    }

    ~CCheckQueue()
    {
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
    std::vector<T> check_mem;
    CCheckQueue<T>* pqueue;
    bool fDone;

public:
    CCheckQueueControl() = delete;
    CCheckQueueControl(const CCheckQueueControl&) = delete;
    CCheckQueueControl& operator=(const CCheckQueueControl&) = delete;
    explicit CCheckQueueControl(CCheckQueue<T> * const pqueueIn, const unsigned int size) : check_mem(), pqueue(pqueueIn), fDone(false)
    {
        // passed queue is supposed to be unused, or NULL
        if (pqueue != NULL) {
            ENTER_CRITICAL_SECTION(pqueue->ControlMutex);
            check_mem.reserve(size);
            pqueue->Setup(&check_mem[0]);
        }
    }

    bool Wait()
    {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }

    //! Deprecated. emplacement Add + Flush are the preferred method for adding
    // checks to the queue.
    void Add(std::vector<T>& vChecks)
    {
        if (pqueue != NULL) {
            auto s = vChecks.size();
            for (T& x : vChecks) {
                check_mem.emplace_back();
                check_mem.back().swap(x);
            }
            pqueue->Add(s);
        }
    }

    //! Add directly constructs a check on the Controller's memory
    // Checks created via emplacement Add won't be executed
    // until a subsequent Flush call.
    template<typename ... Args>
    void Add(Args && ... args)
    {
        if (pqueue != NULL) {
            check_mem.emplace_back(std::forward<Args>(args)...);
        }
    }

    //! FLush is called to inform the worker of new jobs
    void Flush(size_t s)
    {
        if (pqueue != NULL) {
            pqueue->Add(s);
        }
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
        if (pqueue != NULL) {
            pqueue->Cleanup();
            LEAVE_CRITICAL_SECTION(pqueue->ControlMutex);
        }
    }
};

#endif // BITCOIN_CHECKQUEUE_H
