// Copyright (c) 2016 Jeremy Rubin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_CUCKOOCACHE_H_
#define _BITCOIN_CUCKOOCACHE_H_

#include <atomic>
#include <vector>


template <typename T, uint8_t TagSize = 1, bool RemovePadding = true>
struct dual_vector {
    static_assert(sizeof(T) == 32, "Dual vector should only be used for a 32-byte item");
    static_assert(TagSize <= 4, "TagSize too large!");
    static_assert(TagSize != 0, "Must Have a Tag!");
    static const size_t MAIN_BYTES = sizeof(T) - TagSize;
    static const size_t MAIN_PAD_BYTES = TagSize * (!RemovePadding);
    static const size_t TOTAL_MAIN_BYTES = MAIN_BYTES + MAIN_PAD_BYTES;
    static const size_t TAG_BYTES = TagSize;
    typedef std::vector<uint8_t> underlying_storage;
    underlying_storage tag;
    underlying_storage main;
    dual_vector() : tag(), main(){};
    inline void resize(size_t n)
    {
        tag.resize(n * TAG_BYTES);
        main.resize(n * TOTAL_MAIN_BYTES);
    }
    inline void shrink_to_fit()
    {
        tag.shrink_to_fit();
        main.shrink_to_fit();
    }
    inline bool compare_at(size_t n, const T& t) const
    {
        return std::memcmp(&tag[n * TAG_BYTES], t.begin() + MAIN_BYTES, TAG_BYTES) == 0 && std::memcmp(&main[n * TOTAL_MAIN_BYTES], t.begin(), MAIN_BYTES) == 0;
    }
    inline void insert_at(size_t n, const T& t)
    {
        std::memcpy(&tag[n * TAG_BYTES], t.begin() + MAIN_BYTES, TAG_BYTES);
        std::memcpy(&main[n * TOTAL_MAIN_BYTES], t.begin(), MAIN_BYTES);
    }

    inline void swap_at(size_t n, T& t)
    {
        uint8_t* ptr = t.begin();
        uint8_t* end = ptr + MAIN_BYTES;
        for (uint8_t* q = (&main[n * TOTAL_MAIN_BYTES]); ptr != end; ++q, ++ptr)
            std::swap(*q, *ptr);
        end += TAG_BYTES;
        for (uint8_t* q = (&tag[n * TAG_BYTES]); ptr != end; ++q, ++ptr)
            std::swap(*q, *ptr);
    }

    inline void fill_at(size_t n, T& t) const
    {
        std::memcpy(t.begin(), &main[n * TOTAL_MAIN_BYTES], MAIN_BYTES);
        std::memcpy(t.begin() + MAIN_BYTES, &tag[n * TAG_BYTES], TAG_BYTES);
    }
};

template <typename T, bool RemovePadding>
struct dual_vector<T, 0, RemovePadding> {
    static const size_t MAIN_BYTES = sizeof(T);
    static const size_t TAG_BYTES = 0;
    typedef std::vector<T> underlying_storage;
    underlying_storage main;
    dual_vector() : main(){};
    inline void resize(size_t n)
    {
        main.reserve(n);
        T def{};
        for (auto i = 0; i < n; ++i)
            main.push_back(T(def));
    }
    inline void shrink_to_fit()
    {
        main.shrink_to_fit();
    }
    inline bool compare_at(size_t n, const T& t) const
    {
        return main[n] == t;
    }
    inline void insert_at(size_t n, const T& t)
    {
        main[n] = t;
    }

    inline void swap_at(size_t n, T& t)
    {
        std::swap(main[n], t);
    }

    inline void fill_at(size_t n, T& t) const
    {
        t = main[n];
    }
};
/**
 * garbage_collect_flag is a subtype of a std::atomic<uint8_t> 
 * with the benfit that it can be copy constructed, allowing
 * dynamically initialized vectors to be used. This means 
 * it is not entirely thread safe if the container (e.g., std::vector)
 * resizes after startup.
 */
struct garbage_collect_flag : std::atomic<uint8_t> {
    garbage_collect_flag() : std::atomic<uint8_t>(0xff){};
    garbage_collect_flag(const garbage_collect_flag& s) : std::atomic<uint8_t>(s.load()){};
};

/** garbage_collect_flags implements a container for garbage collection flags
 * that is only thread unsafe on calls to resize. This class bit-packs collection
 * flags for memory efficiency.
 *
 * All operations are std::memory_order_relaxed so external mechanisms must
 * ensure that writes and reads are properly synchronized.
 *
 * On resize(n), all bits up to n are marked.
 *
 * Under the hood, because it is an 8-bit type, it makes sense to use a multiple
 * of 8 for resize, but it will be safe if that is not the case as well.
 *
 */
template <typename size_type_in>
class garbage_collect_flags
{
    std::vector<garbage_collect_flag> v;

public:
    typedef size_type_in size_type;
    garbage_collect_flags() : v(){};
    inline void resize(size_type s)
    {
        v.resize((s / 8) + (s % 8 != 0));
    }
    inline void shrink_to_fit()
    {
        v.shrink_to_fit();
    }
    inline void mark(size_type s)
    {
        v[s / 8].fetch_or(1 << (s % 8), std::memory_order_relaxed);
    }

    inline void unmark(size_type s)
    {
        v[s / 8].fetch_and(~(1 << (s % 8)), std::memory_order_relaxed);
    }

    inline bool is_marked(size_type s)
    {
        return (1 << (s % 8)) & v[s / 8].load(std::memory_order_relaxed);
    }
};
template <typename Key, typename Hash, uint8_t HashLimit = 10, uint8_t TagSize = 1, bool RemovePadding = true>
class CuckooCache
{
    static_assert(sizeof(Key) == 32, "Invalid Key Size.");

public:
    // (Most Of) The standard container typedefs, for compatibility, along with
    // a few custom ones pertaining to this class (made private)
    typedef Key key_type;
    typedef key_type value_type;

private:
    typedef dual_vector<value_type, TagSize, RemovePadding> underlying_storage;
    typedef uint8_t recursion_limit_type;

public:
    typedef uint32_t size_type;
    typedef Hash hasher;
    static const uint8_t hash_limit = HashLimit;

private:
    /** set stores all the keys */
    underlying_storage set;

    /** The garbage_collect_flags array is marked mutable because we want
     * garbage collection to be allowed to occur from const methods */
    mutable garbage_collect_flags<size_type> flags;

    /** size stores the total available slots in the hash table */
    size_type size;

    /** hash_function is a const instance of the hash function. It cannot be
     * static or initialized at call time as it may have internal state (such as
     * a nonce.
     * */
    const hasher hash_function;


    /** convenience for not having to write out the modulus everywhere.
     */
    recursion_limit_type depth_limit;
    inline size_type compute_hash(const value_type& t, recursion_limit_type n) const
    {
        return hash_function(t, n) % size;
    }

public:
    /** We must always construct a CuckooCache with one element, otherwise
     * it could segfault on operations.
     */
    CuckooCache() : set(), flags(), size(), hash_function(), depth_limit()
    {
        resize(1);
    }

    /** Insert loops depth_limit times trying to insert a hash
     * at various locations via the Cuckoo Algorithm
     *
     * It drops the last element if it runs out of depth.
     *
     * Note: We trample on the passed in key to avoid having to copy any memory
     * needlessly. There is no use case which actually needs that key to be 
     * preserved
     *
     * TODO: This is technically sub optimal because we swap onto the last hash
     * looked at but we should swap onto the one that will result in minimal
     * moves of memory. That's expensive to compute though, so "whatever".
     *
     * TODO: Optimize the order of hashes we look at; theoretically there
     * could be some value in giving insert and find for speed
     *
     *
     */
    inline void insert(value_type& t)
    {
        for (auto i = 0; i < depth_limit; ++i) {
            // Check that the value has not been inserted already,
            // and make sure it's not marked for garbage collection
            auto it = find(t);
            if (it != end())
                return un_garbage_collect(it);
            size_type h{0};
            // Look at each hash location and put it in if
            // we find a collected location
            for (uint8_t n = 0; n < hash_limit; ++n) {
                h = compute_hash(t, n);
                // In this case, it is safe to just replace the old data
                if (flags.is_marked(h)) {
                    set.insert_at(h, t);
                    flags.unmark(h);
                    return;
                }
            }
            // We must make a copy because the table must be in accurate state before recursing
            set.swap_at(h, t);
        }
    }

    /* find iterates through the hash locations for a given key
     * and checks to see if it is present. 
     *
     * Find does not check garbage collected state, so
     *
     * auto it = find(x)
     * garbage_collect(it)
     * contains(x)
     *
     * executed on a single thread will always succed
     *
     * find returns a const_iterator to the value if it is
     * present, or end() if it is not.
     */
    inline size_type find(const value_type& t) const
    {
        for (uint8_t n = 0; n < hash_limit; ++n) {
            size_type h = compute_hash(t, n);
            if (set.compare_at(h, t))
                return h;
        }
        return end();
    }
    /* contains is much like find, but returns a bool rather
     * than an iterator
     */
    inline bool contains(const value_type& t) const
    {
        for (auto i = 0; i < hash_limit; ++i)
            if (set.compare_at(compute_hash(t, i), t))
                return true;
        return false;
    }
    /* end returns a const_iterator to the end of the set. Used to check that
     * find did not return anything */
    inline size_type end() const
    {
        return size + 1;
    }

    /** rehash reinserts every element of the set into itself. This should be
     * done after a resize, and never really otherwise. It is not guaranteed
     * to preserve all values currently in the set
     */
    void rehash(size_type nprev)
    {
        for (auto i = 0; i < nprev; ++i) {
            if (flags.is_marked(i))
                continue;
            value_type t;
            set.fill_at(i, t);
            insert(t);
        }
    }

    /** resize asjusts the container to store up to new_size elements
     *
     * Not thread safe. Invalidates all iterators.
     *
     * If new_size < old_size, the array is first rehashed and then resized such
     * that all elements can be reinserted.
     *
     * If new_size > old_size the array is resized and then rehashed such that
     * all memory locations should be valid.
     *
     * If new_size == old_size, has no effect.
     *
     *
     **/
    void resize(size_type new_size)
    {
        // n must be at least one otherwise errors can occur.
        new_size = std::max(1u, new_size);
        if (new_size == size)
            return;

        bool downsizing = new_size < size;
        if (downsizing) {
            auto nprev = size;
            size = new_size;
            // rehash before clearing the memory with
            // a resize
            rehash(nprev);
            set.resize(size);
            flags.resize(size);

            flags.shrink_to_fit();
            set.shrink_to_fit();
        } else {
            // resize before increasing memory so all locations exist
            set.resize(new_size);
            flags.resize(new_size);
            rehash(size);
            size = new_size;
        }
        depth_limit = static_cast<recursion_limit_type>(std::log2(static_cast<float>(size)));
    }

    /** resize bytes is a convenience function which accounts for internal
     * memory usage when deciding how many elements to store.
     */
    void resize_bytes(size_t bytes)
    {
        auto bytes_free = bytes - sizeof(CuckooCache<key_type, hasher>);
        auto n = 0;
        if (RemovePadding)
            n = (8 * bytes_free) / (8 * sizeof(value_type) + sizeof(std::atomic<uint8_t>));
        else
            n = (8 * bytes_free) / (8 * (sizeof(value_type) + TagSize) + sizeof(std::atomic<uint8_t>));
        resize(n);
    }


    /** garbage_collect marks a key or iterator to a key as collected. Threadsafe without any concurrent insert. */
    void garbage_collect(const value_type& t) const
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void garbage_collect(size_type n) const
    {
        flags.mark(n);
    }

    /** un-garbage_collect marks a key or iterator to a key as not-collected. Threadsafe without any concurrent insert. */
    void un_garbage_collect(const value_type& t) const
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void un_garbage_collect(size_type n) const
    {
        flags.unmark(n);
    }
};

#endif
