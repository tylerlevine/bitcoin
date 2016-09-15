
#ifndef _BITCOIN_CUCKOOCACHE_H_
#define _BITCOIN_CUCKOOCACHE_H_

#include <atomic>
#include <vector>
#include "util.h"
#include <cinttypes>
struct garbage_collect_flag : std::atomic_bool {
    garbage_collect_flag() : std::atomic_bool(true){};
    garbage_collect_flag(const garbage_collect_flag& s) : std::atomic_bool(s.load()){};
};
template <typename T>
T defualt_constructor_of() {
    return T();
}
template <typename T, typename H>
class CuckooCache
{
    private:
    std::vector<T> set;
    mutable std::vector<garbage_collect_flag> flags;
    uint32_t mod;
    uint32_t depth_limit;
    H hash;
    static const size_t MASK = 0xFFFFFFFF;
    T unsafe_value;
    void insert(const T& t, bool pos, uint32_t depth)
    {
        // If the entry is unsafe_value, no need to fill
        if (t == unsafe_value)
            return;
        // Check that the value has not been inserted already,
        // and make sure it's not marked for garbage collection
        auto it = find(t);
        if (it != end())
            return un_garbage_collect(it);
        uint32_t h = (MASK & (hash(t) >> (pos * 32))) % mod;
        // In this case, it is safe to just replace the old data
        if (flags[h].load() == true) {
            set[h] = t;
            flags[h].store(false);
            return;
        }
        // The data here has never been filled/explicitly deleted
        // And it has not been marked for collection
        if (set[h] == unsafe_value) {
            set[h] = t;
            return;
        }
        // If we haven't reached our recursion limit, we'll try
        // to move the displaced key
        if (depth) {
            // We must make a copy because the table must be in accurate state before recursing
            // We added a more efficient memcpy constructor to base_blob to make this hurt less.
            const T t_copy{set[h]};
            set[h] = t;
            insert(t_copy, !pos, depth - 1);
        }
    }

public:
    CuckooCache() : unsafe_value()
    {
        setup(1);
    }
    void insert(const T& t)
    {
        
        insert(t, false, depth_limit);
    }
    typename std::vector<T>::iterator find(const T& t)
    {
        uint64_t bits = hash(t);
        uint32_t h = (MASK & bits) % mod;
        if (set[h] == t)
            return set.begin() + h;
        h = (bits >> 32) % mod;
        if (set[h] == t)
            return set.begin() + h;
        return set.end();
    }
    bool contains(const T& t)
    {
        uint64_t bits = hash(t);
        return set[(MASK & bits) % mod] == t || set[(bits >> 32) % mod] == t;
    }

    typename std::vector<T>::iterator end()
    {
        return set.end();
    }
    void setup_use_size(size_t bytes) {
        bytes -= sizeof(CuckooCache<T, H>);
        auto n = bytes/(sizeof(T) + sizeof(std::atomic<bool>));
        setup(n);
    }
    void setup(uint32_t n)
    {
        // n must be at least one otherwise errors can occur.
        n = std::max(1u, n);
        if (n == set.size())
            return;
        LogPrintf("Resetting SigCache to store %" PRIu32 " elements \n", n);
        set.resize(0);
        flags.resize(0);
        mod = (n);
        set.reserve(n);
        for (auto i = 0; i < n; ++i)
            set.push_back(unsafe_value);
        flags.resize(mod);
        depth_limit = std::ilogb(n);
    }
    void multiply_depths(size_t n)
    {
        depth_limit *= n;
    }
    void garbage_collect(const T& t)
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void garbage_collect(typename std::vector<T>::iterator it)
    {
        flags[it - set.begin()].store(true);
    }

    void un_garbage_collect(const T& t)
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void un_garbage_collect(typename std::vector<T>::iterator it)
    {
        flags[it - set.begin()].store(false);
    }
};
#endif
