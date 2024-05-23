#include <bits/stdc++.h>

#define ROUNDS 10
#define BITS 32
#define MASK ((1LL << BITS) - 1)
#define MUL(x, y) ((x * y) & MASK)
#define ADD(x, y) ((x + y) & MASK)
#define SUB(x, y) ((x - y + (1LL << BITS)) & MASK)
#define ROL(x, r) (((x << (r)) | (x >> (BITS - (r)))) & MASK)
#define ROR(x, r) (((x >> (r)) | ((x << (BITS - (r))))) & MASK)

using namespace std;

const uint RC[] = {2667589438, 3161395992, 3211084506, 3202806575, 827352482, 3632865942, 1447589438, 3161338992};

uint round_f(uint x, uint k, int i)
{
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROR(SUB(k, x), 29)) ^ ADD(k, MUL((uint)i, 0x13371337LL));
}

vector<uint> key_schedule(uint key_l, uint key_r, int n_rounds)
{
    vector<uint> keys;
    keys.push_back(key_l);

    for (int i = 0; i < n_rounds - 2; i++)
    {
        uint tmp = key_l;
        key_l = key_r;
        key_r = ADD(tmp, round_f(key_r, RC[i], i + 1));
        keys.push_back(key_l);
    }

    keys.push_back(key_r);
    return keys;
}

vector<uint> reverse_schedule(uint key_l, uint key_r, int n_rounds)
{
    vector<uint> keys(10);
    keys[9] = key_r;
    for (int i = n_rounds - 2; i > 0; i--)
    {
        uint tmp = key_r;
        key_r = key_l;
        key_l = SUB(tmp, round_f(key_r, RC[i - 1], i));
        keys[i] = (key_r);
    }
    keys[0] = key_l;
    return keys;
}

array<uint, 2> encrypt_block(uint l, uint r, vector<uint> &round_keys, int n_rounds)
{
    for (int i = 0; i < n_rounds; i++)
    {
        uint tmp = l;
        l = r;
        r = ADD(tmp, round_f(r, round_keys[i], i + 1));
    }

    return {l, r};
}

int main()
{
    vector<uint8_t> nb_right_pairs = vector<uint8_t>(1L << 32, 0);
    vector<array<uint, 8>> data;
    size_t l;
    cin >> l;
    for (size_t i = 0; i < l; i++)
    {
        uint pl1, pr1, pl2, pr2, l1, r1, l2, r2;
        cin >> pl1;
        cin >> pr1;
        cin >> pl2;
        cin >> pr2;
        cin >> l1;
        cin >> r1;
        cin >> l2;
        cin >> r2;
        data.push_back({pl1, pr1, pl2, pr2, l1, r1, l2, r2});
    }

    for (array<uint, 8> l : data)
    {
#pragma omp parallel for shared(l, nb_right_pairs)
        for (size_t i = 0; i < (1L << 32); i++)
        {
            if (SUB(l[5], round_f(l[4], i, 10)) == SUB(l[7], round_f(l[6], i, 10)))
                nb_right_pairs[i]++;
        }
    }
    uint max_right_pairs = *max_element(nb_right_pairs.begin(), nb_right_pairs.end());
    vector<uint> possible_last_round_keys = vector<uint>();
#pragma omp parallel for shared(possible_last_round_keys, nb_right_pairs, max_right_pairs)
    for (size_t i = 0; i < 1L << 32; i++)
        if (nb_right_pairs[i] == max_right_pairs)
        {
#pragma omp critical
            possible_last_round_keys.push_back(i);
        }

    vector<array<uint, 4>> new_data;
    for (array<uint, 8> l : data)
    {
        new_data.push_back({l[0], l[1], l[4], l[5]});
        new_data.push_back({l[2], l[3], l[6], l[7]});
    }

    vector<pair<uint, uint>> pos_keys;
    for (uint key_r : possible_last_round_keys)
    {
#pragma omp parallel for shared(new_data, pos_keys)
        for (size_t i = 0; i < 1L << 32; i++)
        {
            auto keys = reverse_schedule(i, key_r, 10);
            auto res = encrypt_block(new_data[0][0], new_data[0][1], keys, 10);
            if ((res[0] == new_data[0][2]) && (res[1] == new_data[0][3]))
            {
#pragma omp critical
                pos_keys.push_back({keys[0], keys[1]});
            }
        }
    }

    size_t j = 1;
    while (pos_keys.size() > 1 && j < new_data.size())
    {
        vector<pair<uint, uint>> tmp;
#pragma omp parallel for shared(new_data, pos_keys, tmp)
        for (pair<uint, uint> k : pos_keys)
        {
            auto keys = key_schedule(k.first, k.second, 10);
            auto res = encrypt_block(new_data[j][0], new_data[j][1], keys, 10);
            if ((res[0] == new_data[j][2]) && (res[1] == new_data[j][3]))
            {
#pragma omp critical
                tmp.push_back(k);
            }
        }
        pos_keys = tmp;
        j += 1;
    }

    unsigned long long master_key = 0;

    if (pos_keys.size() >= 1)
    {
        master_key = ((unsigned long long)pos_keys[0].first << 32) | pos_keys[0].second;
    }
    std::cout << master_key << endl;
}
