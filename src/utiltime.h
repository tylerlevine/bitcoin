// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILTIME_H
#define BITCOIN_UTILTIME_H

#include <stdint.h>
#include <string>
#include <atomic>

int64_t GetTime();
int64_t GetTimeMillis();
int64_t GetTimeMicros();
int64_t GetLogTimeMicros();
void SetMockTime(int64_t nMockTimeIn);
void MilliSleep(int64_t n);

/*
 * Fake lock that satisfies the BasicLockable concept
 * Useful for waiting on a condition variable with an atomic predicate
 *
*/
struct CNullLock
{
    static inline void lock() {}
    static inline void unlock() {}
};

/*
 * Sleep for the stated period of time, interruptible by clearing the flag and notifying the condvar.
 * @param   rel_time maximum time to wait. Should be a std::chrono::duration.
 * @param   cond condition variable to wait on. Usually a std::condition_variable or std::condition_variable_any
 * @param   flag reference to a flag that will be cleared if the sleep should be interrupted
 * @returns false if the sleep was interrupted, true otherwise
 */
template <typename Duration, typename Cond>
inline bool InterruptibleSleep(const Duration& rel_time, Cond& cond, std::atomic_flag& flag)
{
    static const constexpr CNullLock nullLock{};
    return !cond.wait_for(nullLock, rel_time, [&flag](){ return !flag.test_and_set(); });
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime);

#endif // BITCOIN_UTILTIME_H
