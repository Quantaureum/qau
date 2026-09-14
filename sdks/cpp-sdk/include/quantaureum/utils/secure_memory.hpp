// Quantaureum C++ SDK source, version 1.0.0.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace quantaureum {
namespace utils {

/**
 * @brief Secure array that zeroes memory on destruction
 *
 * Provides automatic secure memory clearing for sensitive data like private keys.
 * Uses volatile pointers to prevent compiler optimization and mlock to prevent
 * swapping to disk.
 *
 * @tparam T Element type (typically uint8_t)
 * @tparam N Array size
 */
template<typename T, size_t N>
class SecureArray {
public:
    SecureArray() : locked_(false) {
        std::memset(data_, 0, sizeof(data_));
    }

    explicit SecureArray(const std::array<T, N>& arr) : locked_(false) {
        std::copy(arr.begin(), arr.end(), data_);
    }

    ~SecureArray() {
        secureZero();
        if (locked_) {
            unlock();
        }
    }

    // Disable copy to prevent sensitive data duplication
    SecureArray(const SecureArray&) = delete;
    SecureArray& operator=(const SecureArray&) = delete;

    // Enable move
    SecureArray(SecureArray&& other) noexcept : locked_(other.locked_) {
        std::copy(other.data_, other.data_ + N, data_);
        other.secureZero();
        other.locked_ = false;
    }

    SecureArray& operator=(SecureArray&& other) noexcept {
        if (this != &other) {
            secureZero();
            if (locked_) {
                unlock();
            }
            std::copy(other.data_, other.data_ + N, data_);
            locked_ = other.locked_;
            other.secureZero();
            other.locked_ = false;
        }
        return *this;
    }

    /**
     * @brief Lock memory to prevent swapping to disk
     * @return true if successful, false otherwise
     */
    bool lock() {
        if (locked_) {
            return true;
        }

#ifdef _WIN32
        if (VirtualLock(data_, sizeof(data_))) {
            locked_ = true;
            return true;
        }
        return false;
#else
        if (mlock(data_, sizeof(data_)) == 0) {
            locked_ = true;
            return true;
        }
        return false;
#endif
    }

    /**
     * @brief Unlock memory
     */
    void unlock() {
        if (!locked_) {
            return;
        }

#ifdef _WIN32
        VirtualUnlock(data_, sizeof(data_));
#else
        munlock(data_, sizeof(data_));
#endif
        locked_ = false;
    }

    /**
     * @brief Securely zero the memory
     *
     * Uses volatile pointer to prevent compiler optimization
     */
    void secureZero() {
        volatile T* p = data_;
        for (size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }

    // Array access
    T* data() { return data_; }
    const T* data() const { return data_; }

    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }

    T* begin() { return data_; }
    const T* begin() const { return data_; }

    T* end() { return data_ + N; }
    const T* end() const { return data_ + N; }

    constexpr size_t size() const { return N; }

    /**
     * @brief Convert to std::array (creates a copy)
     */
    std::array<T, N> toArray() const {
        std::array<T, N> result;
        std::copy(data_, data_ + N, result.begin());
        return result;
    }

    /**
     * @brief Copy from std::array
     */
    void fromArray(const std::array<T, N>& arr) {
        std::copy(arr.begin(), arr.end(), data_);
    }

private:
    T data_[N];
    bool locked_;
};

/**
 * @brief Secure vector that zeroes memory on destruction
 */
template<typename T>
class SecureVector {
public:
    SecureVector() : locked_(false) {}

    explicit SecureVector(size_t size) : data_(size), locked_(false) {}

    explicit SecureVector(const std::vector<T>& vec) : data_(vec), locked_(false) {}

    ~SecureVector() {
        secureZero();
        if (locked_) {
            unlock();
        }
    }

    // Disable copy
    SecureVector(const SecureVector&) = delete;
    SecureVector& operator=(const SecureVector&) = delete;

    // Enable move
    SecureVector(SecureVector&& other) noexcept
        : data_(std::move(other.data_)), locked_(other.locked_) {
        other.locked_ = false;
    }

    SecureVector& operator=(SecureVector&& other) noexcept {
        if (this != &other) {
            secureZero();
            if (locked_) {
                unlock();
            }
            data_ = std::move(other.data_);
            locked_ = other.locked_;
            other.locked_ = false;
        }
        return *this;
    }

    bool lock() {
        if (locked_ || data_.empty()) {
            return locked_;
        }

#ifdef _WIN32
        if (VirtualLock(data_.data(), data_.size() * sizeof(T))) {
            locked_ = true;
            return true;
        }
        return false;
#else
        if (mlock(data_.data(), data_.size() * sizeof(T)) == 0) {
            locked_ = true;
            return true;
        }
        return false;
#endif
    }

    void unlock() {
        if (!locked_ || data_.empty()) {
            return;
        }

#ifdef _WIN32
        VirtualUnlock(data_.data(), data_.size() * sizeof(T));
#else
        munlock(data_.data(), data_.size() * sizeof(T));
#endif
        locked_ = false;
    }

    void secureZero() {
        if (!data_.empty()) {
            volatile T* p = data_.data();
            for (size_t i = 0; i < data_.size(); ++i) {
                p[i] = 0;
            }
        }
    }

    // Vector access
    T* data() { return data_.data(); }
    const T* data() const { return data_.data(); }

    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }

    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void resize(size_t size) { data_.resize(size); }

    std::vector<T> toVector() const { return data_; }

private:
    std::vector<T> data_;
    bool locked_;
};

} // namespace utils
} // namespace quantaureum
