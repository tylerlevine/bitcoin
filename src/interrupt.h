// Copyright (c) 2016 Jeremy Rubin
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERRUPT_H
#define BITCOIN_INTERRUPT_H
#include <atomic>
#include <mutex>
#include <condition_variable>
struct Interruption {};
class interruption_point {

    std::atomic_flag f;

    public:

    interruption_point() {
       f.test_and_set();
    }

    bool check_interrupt() {
        if (!f.test_and_set()) {
            throw Interruption{};
        }
        return false;
    }

    void interrupt() {
        f.clear();
    }

    template <typename Duration>
    inline void InterruptibleSleep(const Duration& rel_time, std::condition_variable& cond)
    {
        std::mutex interruptMutex;
        std::unique_lock<std::mutex> lock(interruptMutex);
        if (cond.wait_for(lock, rel_time, [this](){ return !f.test_and_set(); }))
            throw Interruption{};
    }
};

#endif // BITCOIN_INTERRUPT_H
