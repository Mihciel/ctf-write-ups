#include <bits/stdc++.h>
#include <random>
#include <iostream>
#include <format>

#define ROUNDS 10
#define BITS 32
#define MASK ((1LL << BITS) - 1)
#define MUL(x, y) ((x * y) & MASK)
#define ADD(x, y) ((x + y) & MASK)
#define SUB(x, y) ((x - y + (1LL << BITS)) & MASK)
#define ROL(x, r) (((x << (r)) | (x >> (BITS - (r)))) & MASK)
#define ROR(x, r) (((x >> (r)) | ((x << (BITS - (r))))) & MASK)

uint round_f(uint x, uint k, int i)
{
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROR(SUB(k, x), 29)) ^ ADD(k, MUL((uint)i, 0x13371337LL));
}

int main(int argc, char const *argv[])
{
    std::mt19937 gen(0);
    std::uniform_int_distribution<uint> distrib(0, MASK);
    std::uniform_int_distribution<int> distrib2(1, 10);
    std::vector<uint8_t> nb_differences = std::vector<uint8_t>(1L << 32, 0);
    for (size_t j = 0; j < 50; j++)
    {
        uint x = distrib(gen);
        uint k = distrib(gen);
        int round = distrib2(gen);
        for (size_t d = 1; d < 1L << 32; d++)
        {
            nb_differences[d] += (round_f(x, k, round) == round_f(x + d, k, round));
        }
    }
    std::vector<uint> good_differences = std::vector<uint>();
    for (size_t d = 1; d < 1L << 32; d++)
        if (nb_differences[d])
            good_differences.push_back(d);
    std::cout << good_differences.size() << std::endl;

    std::vector<uint> better_differences = std::vector<uint>();
    for (uint d : good_differences)
    {
        size_t count = 0;
        for (size_t j = 0; j < 10000; j++)
        {
            uint x = distrib(gen);
            uint k = distrib(gen);
            int round = distrib2(gen);
            count += (round_f(x, k, round) == round_f(x + d, k, round));
        }
        if (count > 150)
            better_differences.push_back(d);
    }
    std::cout << better_differences.size() << std::endl;

    for (uint d : better_differences)
    {
        size_t count = 0;
        for (size_t j = 0; j < 100000000; j++)
        {
            uint x = distrib(gen);
            uint k = distrib(gen);
            int round = distrib2(gen);
            count += (round_f(x, k, round) == round_f(x + d, k, round));
        }
        std::cout << std::setfill('0') << std::setw(8) << std::hex << d << " " << count / 1e8 << std::endl;
    }

    return 0;
}
