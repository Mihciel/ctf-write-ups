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
    std::uniform_int_distribution<uint> distrib2(0, 7);
    uint differences[8] = {0x3fffc00, 0x4000400, 0x7fff800, 0x8000800, 0xffff000, 0x10001000, 0xf0001000, 0xf8000800};
    std::vector<uint8_t> possible_keys = std::vector<uint8_t>(1L << 32, 0);
    for (size_t nb_right_pairs = 1; nb_right_pairs < 11; nb_right_pairs++)
    {
        size_t res_count = 0;
        for (size_t exp_index = 0; exp_index < 10; exp_index++)
        {
            std::fill(possible_keys.begin(), possible_keys.end(), 0);
            std::vector<std::array<uint, 4>> data = std::vector<std::array<uint, 4>>();
            uint k = distrib(gen);
            for (size_t i = 0; i < nb_right_pairs; i++)
            {
                uint l = distrib(gen);
                uint r = distrib(gen);
                uint d = differences[distrib2(gen)];
                data.push_back({r, l + round_f(r, k, 10), r + d, l + round_f(r + d, k, 10)});
            }
            for (std::array<uint, 4> l : data)
            {
#pragma omp parallel for shared(l, possible_keys)
                for (size_t i = 0; i < (1L << 32); i++)
                {
                    if (SUB(l[1], round_f(l[0], i, 10)) == SUB(l[3], round_f(l[2], i, 10)))
                        possible_keys[i]++;
                }
            }
            for (size_t i = 0; i < (1L << 32); i++)
                res_count += (possible_keys[i] == nb_right_pairs);
        }
        std::cout << nb_right_pairs << " " << (res_count / 1e1) << std::endl;
    }

    return 0;
}
