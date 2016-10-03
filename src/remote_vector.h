#ifndef _BITCOIN_REMOTEVECTOR_H_
#define _BITCOIN_REMOTEVECTOR_H_
#include <memory>
#include <cstddef>
#include <cstdlib>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>





template<typename T, size_t N, typename Size = uint32_t, typename Diff = int32_t>
class remote_vector {
public:
    typedef Size size_type;
    typedef Diff difference_type;
    typedef T value_type;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;

    class iterator {
        T* ptr;
    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T* pointer;
        typedef T& reference;
        typedef std::random_access_iterator_tag iterator_category;
        iterator(T* ptr_) : ptr(ptr_) {}
        T& operator*() const { return *ptr; }
        T* operator->() const { return ptr; }
        T& operator[](size_type pos) { return ptr[pos]; }
        const T& operator[](size_type pos) const { return ptr[pos]; }
        iterator& operator++() { ptr++; return *this; }
        iterator& operator--() { ptr--; return *this; }
        iterator operator++(int) { iterator copy(*this); ++(*this); return copy; }
        iterator operator--(int) { iterator copy(*this); --(*this); return copy; }
        difference_type friend operator-(iterator a, iterator b) { return (&(*a) - &(*b)); }
        iterator operator+(size_type n) { return iterator(ptr + n); }
        iterator& operator+=(size_type n) { ptr += n; return *this; }
        iterator operator-(size_type n) { return iterator(ptr - n); }
        iterator& operator-=(size_type n) { ptr -= n; return *this; }
        bool operator==(iterator x) const { return ptr == x.ptr; }
        bool operator!=(iterator x) const { return ptr != x.ptr; }
        bool operator>=(iterator x) const { return ptr >= x.ptr; }
        bool operator<=(iterator x) const { return ptr <= x.ptr; }
        bool operator>(iterator x) const { return ptr > x.ptr; }
        bool operator<(iterator x) const { return ptr < x.ptr; }
    };

    class reverse_iterator {
        T* ptr;
    public:
        typedef Diff difference_type;
        typedef T value_type;
        typedef T* pointer;
        typedef T& reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        reverse_iterator(T* ptr_) : ptr(ptr_) {}
        T& operator*() { return *ptr; }
        const T& operator*() const { return *ptr; }
        T* operator->() { return ptr; }
        const T* operator->() const { return ptr; }
        reverse_iterator& operator--() { ptr++; return *this; }
        reverse_iterator& operator++() { ptr--; return *this; }
        reverse_iterator operator++(int) { reverse_iterator copy(*this); ++(*this); return copy; }
        reverse_iterator operator--(int) { reverse_iterator copy(*this); --(*this); return copy; }
        bool operator==(reverse_iterator x) const { return ptr == x.ptr; }
        bool operator!=(reverse_iterator x) const { return ptr != x.ptr; }
    };

    class const_iterator {
        const T* ptr;
    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T* pointer;
        typedef const T& reference;
        typedef std::random_access_iterator_tag iterator_category;
        const_iterator(const T* ptr_) : ptr(ptr_) {}
        const_iterator(iterator x) : ptr(&(*x)) {}
        const T& operator*() const { return *ptr; }
        const T* operator->() const { return ptr; }
        const T& operator[](size_type pos) const { return ptr[pos]; }
        const_iterator& operator++() { ptr++; return *this; }
        const_iterator& operator--() { ptr--; return *this; }
        const_iterator operator++(int) { const_iterator copy(*this); ++(*this); return copy; }
        const_iterator operator--(int) { const_iterator copy(*this); --(*this); return copy; }
        difference_type friend operator-(const_iterator a, const_iterator b) { return (&(*a) - &(*b)); }
        const_iterator operator+(size_type n) { return const_iterator(ptr + n); }
        const_iterator& operator+=(size_type n) { ptr += n; return *this; }
        const_iterator operator-(size_type n) { return const_iterator(ptr - n); }
        const_iterator& operator-=(size_type n) { ptr -= n; return *this; }
        bool operator==(const_iterator x) const { return ptr == x.ptr; }
        bool operator!=(const_iterator x) const { return ptr != x.ptr; }
        bool operator>=(const_iterator x) const { return ptr >= x.ptr; }
        bool operator<=(const_iterator x) const { return ptr <= x.ptr; }
        bool operator>(const_iterator x) const { return ptr > x.ptr; }
        bool operator<(const_iterator x) const { return ptr < x.ptr; }
    };

    class const_reverse_iterator {
        const T* ptr;
    public:
        typedef Diff difference_type;
        typedef const T value_type;
        typedef const T* pointer;
        typedef const T& reference;
        typedef std::bidirectional_iterator_tag iterator_category;
        const_reverse_iterator(T* ptr_) : ptr(ptr_) {}
        const_reverse_iterator(reverse_iterator x) : ptr(&(*x)) {}
        const T& operator*() const { return *ptr; }
        const T* operator->() const { return ptr; }
        const_reverse_iterator& operator--() { ptr++; return *this; }
        const_reverse_iterator& operator++() { ptr--; return *this; }
        const_reverse_iterator operator++(int) { const_reverse_iterator copy(*this); ++(*this); return copy; }
        const_reverse_iterator operator--(int) { const_reverse_iterator copy(*this); --(*this); return copy; }
        bool operator==(const_reverse_iterator x) const { return ptr == x.ptr; }
        bool operator!=(const_reverse_iterator x) const { return ptr != x.ptr; }
    };

private:
    struct impl {
        value_type* begin;
        value_type* end;
        value_type* capacity;
        void fix_layout(difference_type new_capacity) {
            size_t size = end - begin;
            begin = (T*) (this+1);
            capacity = begin + new_capacity;
            end = begin + std::min((size_t) new_capacity, size);
        }
        
    };
    impl* ptr;

    bool is_direct() const { return false; }
    T* item_ptr(difference_type pos) { return ptr->begin + pos; }
    const T* item_ptr(difference_type pos) const { return ptr->begin + pos; }

    void change_capacity(size_type new_capacity) {
        ptr = static_cast<impl*>(realloc((void*) ptr, sizeof(impl) + ((size_t)sizeof(T)) * new_capacity));
        ptr->fix_layout(new_capacity);
    }


public:
    void assign(size_type n, const T& val) {
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        while (size() < n) {
            new(static_cast<void*>(ptr->end++)) T(val);
        }
    }

    template<typename InputIterator>
    void assign(InputIterator first, InputIterator last) {
        size_type n = last - first;
        clear();
        if (capacity() < n) {
            change_capacity(n);
        }
        while (first != last) {
            new(static_cast<void*>(ptr->end++)) T(*first);
            ++first;
        }
    }

    remote_vector() : ptr((impl*) std::malloc(sizeof(impl) + N*sizeof(T))) {
        ptr->begin = (T*) ((uintptr_t) ptr+sizeof(impl));
        ptr->end = ptr->begin;
        ptr->capacity = ptr->begin+N;
    }

    explicit remote_vector(size_type n) : remote_vector() {
        resize(n);
    }

    explicit remote_vector(size_type n, const T& val = T()) : remote_vector() {
        change_capacity(n);
        while (size() < n) {
            new(static_cast<void*>(ptr->end++)) T(val);
        }
    }

    template<typename InputIterator>
    remote_vector(InputIterator first, InputIterator last) : remote_vector() {
        size_type n = last - first;
        change_capacity(n);
        while (first != last) {
            new(static_cast<void*>(ptr->end++)) T(*first);
            ++first;
        }
    }

    remote_vector(const remote_vector<T, N, Size, Diff>& other) : remote_vector() {
        change_capacity(other.size());
        const_iterator it = other.begin();
        while (it != other.end()) {
            new(static_cast<void*>(ptr->end++)) T(*it);
            ++it;
        }
    }

    remote_vector& operator=(const remote_vector<T, N, Size, Diff>& other) {
        if (&other == this) {
            return *this;
        }
        resize(0);
        change_capacity(other.size());
        const_iterator it = other.begin();
        while (it != other.end()) {
            new(static_cast<void*>(ptr->end++)) T(*it);
            ++it;
        }
        return *this;
    }

    size_type size() const {
        return ptr->end - ptr->begin;
    }

    bool empty() const {
        return size() == 0;
    }

    iterator begin() { return iterator(item_ptr(0)); }
    const_iterator begin() const { return const_iterator(item_ptr(0)); }
    iterator end() { return iterator(item_ptr(size())); }
    const_iterator end() const { return const_iterator(item_ptr(size())); }

    reverse_iterator rbegin() { return reverse_iterator(item_ptr(size() - 1)); }
    const_reverse_iterator rbegin() const { return const_reverse_iterator(item_ptr(size() - 1)); }
    reverse_iterator rend() { return reverse_iterator(item_ptr(-1)); }
    const_reverse_iterator rend() const { return const_reverse_iterator(item_ptr(-1)); }

    size_t capacity() const {
        return ptr->capacity - ptr->begin;
    }

    T& operator[](size_type pos) {
        return *item_ptr(pos);
    }

    const T& operator[](size_type pos) const {
        return *item_ptr(pos);
    }

    void resize(size_type new_size) {
        if (size() > new_size) {
            erase(item_ptr(new_size), end());
        }
        if (new_size > capacity()) {
            change_capacity(new_size);
        }
        while (size() < new_size) {
            new(static_cast<void*>(ptr->end++)) T();
        }
    }

    void reserve(size_type new_capacity) {
        if (new_capacity > capacity()) {
            change_capacity(new_capacity);
        }
    }

    void shrink_to_fit() {
        change_capacity(size());
    }

    void clear() {
        resize(0);
    }

    iterator insert(iterator pos, const T& value) {
        size_type p = pos - begin();
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        memmove(item_ptr(p + 1), item_ptr(p), (size() - p) * sizeof(T));
        ++(ptr->end);
        new(static_cast<void*>(item_ptr(p))) T(value);
        return iterator(item_ptr(p));
    }

    void insert(iterator pos, size_type count, const T& value) {
        size_type p = pos - begin();
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
        ptr->end += count;
        for (size_type i = 0; i < count; i++) {
            new(static_cast<void*>(item_ptr(p + i))) T(value);
        }
    }

    template<typename InputIterator>
    void insert(iterator pos, InputIterator first, InputIterator last) {
        size_type p = pos - begin();
        difference_type count = last - first;
        size_type new_size = size() + count;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        memmove(item_ptr(p + count), item_ptr(p), (size() - p) * sizeof(T));
        ptr->end += count;
        while (first != last) {
            new(static_cast<void*>(item_ptr(p))) T(*first);
            ++p;
            ++first;
        }
    }

    iterator erase(iterator pos) {
        return erase(pos, pos + 1);
    }

    iterator erase(iterator first, iterator last) {
        iterator p = first;
        char* endp = (char*)&(*end());
        while (p != last) {
            (*p).~T();
            --(ptr->end);
            ++p;
        }
        memmove(&(*first), &(*last), endp - ((char*)(&(*last))));
        return first;
    }

    void push_back(const T& value) {
        size_type new_size = size() + 1;
        if (capacity() < new_size) {
            change_capacity(new_size + (new_size >> 1));
        }
        new(item_ptr(size())) T(value);
        ++(ptr->end);
    }

    void pop_back() {
        erase(end() - 1, end());
    }

    T& front() {
        return *item_ptr(0);
    }

    const T& front() const {
        return *item_ptr(0);
    }

    T& back() {
        return *item_ptr(size() - 1);
    }

    const T& back() const {
        return *item_ptr(size() - 1);
    }

    void swap(remote_vector<T, N, Size, Diff>& other) {
        std::swap(ptr, other.ptr);
    }

    ~remote_vector() {
        clear();
        std::free(ptr);
    }

    bool operator==(const remote_vector<T, N, Size, Diff>& other) const {
        if (other.size() != size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while (b1 != e1) {
            if ((*b1) != (*b2)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return true;
    }

    bool operator!=(const remote_vector<T, N, Size, Diff>& other) const {
        return !(*this == other);
    }

    bool operator<(const remote_vector<T, N, Size, Diff>& other) const {
        if (size() < other.size()) {
            return true;
        }
        if (size() > other.size()) {
            return false;
        }
        const_iterator b1 = begin();
        const_iterator b2 = other.begin();
        const_iterator e1 = end();
        while (b1 != e1) {
            if ((*b1) < (*b2)) {
                return true;
            }
            if ((*b2) < (*b1)) {
                return false;
            }
            ++b1;
            ++b2;
        }
        return false;
    }

    size_t allocated_memory() const {
        return ((size_t)(sizeof(T))) * capacity() + sizeof(impl);
    }
};
#endif
