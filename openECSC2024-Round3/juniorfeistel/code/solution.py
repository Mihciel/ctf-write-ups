from pwn import remote, process
from random import randrange

while True:
    d = 67109888
    # r = process("./JuniorFeistel")
    r = remote("juniorfeistel.challs.open.ecsc2024.it", 38014)
    r.recvuntil(b"encrypt?\n")
    ps = []
    for _ in range(7000000 // 31):
        x = randrange(2**32)
        for j in range(31):
            ps.append((((j * d) % 2**32) << 32) + x)
    r.sendline(" ".join([str(x) for x in ps]).encode())
    r.sendline(b"-1")
    cs = [
        tuple(map(int, l.split(", ")))
        for l in r.recvuntil(b"Key?").decode().splitlines()[:-1]
    ]
    filtered_pairs = []
    for i in range(7000000 // 31):
        for j in range(30):
            if cs[31 * i + j + 1][0] - cs[31 * i + j][0] == d:
                filtered_pairs.append(
                    (
                        ps[31 * i + j],
                        ps[31 * i + j + 1],
                        cs[31 * i + j],
                        cs[31 * i + j + 1],
                    )
                )
        for j in range(29):
            if cs[31 * i + j + 2][0] - cs[31 * i + j][0] == 2 * d:
                filtered_pairs.append(
                    (
                        ps[31 * i + j],
                        ps[31 * i + j + 2],
                        cs[31 * i + j],
                        cs[31 * i + j + 2],
                    )
                )
        for j in range(27):
            if cs[31 * i + j + 4][0] - cs[31 * i + j][0] == 4 * d:
                filtered_pairs.append(
                    (
                        ps[31 * i + j],
                        ps[31 * i + j + 4],
                        cs[31 * i + j],
                        cs[31 * i + j + 4],
                    )
                )

    print(len(filtered_pairs))
    # guess key
    p = process(
        "./deduce"
    )  # compile deduce_key.cpp (with openmp enabled) if this file doesn't exist
    p.sendline(f"{len(filtered_pairs)}".encode())

    for x in filtered_pairs:
        p.sendline(
            f"{x[0]>>32} {x[0]&0xffffffff} {x[1]>>32} {x[1]&0xffffffff} {x[2][0]} {x[2][1]} {x[3][0]} {x[3][1]}".encode()
        )
    k = int(p.recvline(timeout=10000).decode())
    p.close()
    print(k)
    r.sendline(str(k).encode())
    res = r.recvall()
    r.close()
    if b"openECSC" in res or b"Flag" in res:
        print(res)
        exit()
