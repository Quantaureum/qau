// Quantaureum C++ SDK source, version 1.0.0.
#include "quantaureum/utils/secure_random.hpp"
#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

namespace quantaureum {
namespace utils {

void SecureRandom::generateBytes(uint8_t* buffer, size_t size) {
    if (buffer == nullptr || size == 0) {
        throw std::invalid_argument("Invalid buffer or size");
    }

#ifdef _WIN32
    // Windows: Use BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buffer,
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed with status code");
    }
#else
    // Linux/Unix: Try getrandom() first (available since Linux 3.17)
    #ifdef __linux__
    ssize_t result = getrandom(buffer, size, 0);
    if (result == static_cast<ssize_t>(size)) {
        return;
    }
    if (result >= 0) {
        throw std::runtime_error("getrandom returned insufficient bytes");
    }
    // If getrandom fails, fall back to /dev/urandom
    #endif

    // Fallback: Read from /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("Failed to open /dev/urandom: " + std::string(strerror(errno)));
    }

    size_t total_read = 0;
    while (total_read < size) {
        ssize_t bytes_read = read(fd, buffer + total_read, size - total_read);
        if (bytes_read < 0) {
            close(fd);
            throw std::runtime_error("Failed to read from /dev/urandom: " + std::string(strerror(errno)));
        }
        if (bytes_read == 0) {
            close(fd);
            throw std::runtime_error("Unexpected EOF from /dev/urandom");
        }
        total_read += bytes_read;
    }
    close(fd);
#endif
}

std::vector<uint8_t> SecureRandom::generateBytes(size_t size) {
    std::vector<uint8_t> result(size);
    generateBytes(result.data(), size);
    return result;
}

uint32_t SecureRandom::generateUInt32() {
    uint32_t result;
    generateBytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

uint64_t SecureRandom::generateUInt64() {
    uint64_t result;
    generateBytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

} // namespace utils
} // namespace quantaureum
