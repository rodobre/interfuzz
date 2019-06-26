#pragma once
#include <cstdint>

namespace XorshiftPRNG
{
    static uint64_t internal_seed = 0x406ffab3c0932f73;

    template <typename T>
    T GetRandomBits(const uint64_t bits = sizeof(T) * 0x08u, const uint64_t seed = internal_seed)
    {
        internal_seed = seed;
        internal_seed ^= internal_seed << 13;
        internal_seed ^= internal_seed >> 7;
        internal_seed ^= internal_seed << 17;

        return static_cast<T>(internal_seed & ((1llu << bits) - 1) );
    }

    uint8_t GetRandomByte()
    {
        return GetRandomBits<uint8_t>();
    }

    uint16_t Get2RandomBytes()
    {
        return GetRandomBits<uint16_t>();
    }

    uint32_t Get4RandomBytes()
    {
        return GetRandomBits<uint32_t>();
    }

    uint64_t Get8RandomBytes()
    {
        return GetRandomBits<uint64_t>();
    }
};