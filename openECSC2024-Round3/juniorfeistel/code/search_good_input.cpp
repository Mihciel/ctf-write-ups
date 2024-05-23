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
    uint d = 0x3fffc00;
    std::mt19937 gen(0);
    std::uniform_int_distribution<uint> distrib(0, MASK);
    std::uniform_int_distribution<int> distrib2(1, 10);
    std::vector<size_t> nb_collisions = std::vector<size_t>(1L << 10, 0);
    for (size_t j = 0; j < 10000; j++)
    {
        uint x = distrib(gen) & 0xfffffc00;
        uint k = distrib(gen);
        for (size_t y = 0; y < 1L << 10; y++)
        {
            nb_collisions[y] += (round_f(x + y, k, 1) == round_f(x + y + d, k, 1));
        }
    }
    for (size_t y = 0; y < 1L << 10; y++)
    {
            std::cout << std::setfill('0') << std::setw(3) << std::hex << y << " " << nb_collisions[y]/1e5 << std::endl;

    }


    return 0;
}
