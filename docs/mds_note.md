# Note on Used MDS

I am unfamiliar with why AES use the constant
used in mixcolumns:

    -------------
    |02|03|01|01|
    |01|02|03|01|
    |01|01|02|03|
    |03|01|01|02|
    -------------

turned out it's called Maximum Distance Separable (MDS) matrices? based on:

(https://doi.org/10.1007/978-3-030-51938-4_6)

now, because the state is 2x2 array, we cannot use the 4x4 AES MDS array. solution? use AES MDS but only until 4th column and row (1 base index here).

    -------
    |02|03|
    |01|02|
    -------

(determinant is non-zero, therefore invertible)

Now i tried to inverse AES MDS with sagemath using AES irreducible polynomial, and the result looks okay (correct :D). Here's the code:

    F.<a> = GF(2^8, modulus=x^8 +x^4 + x^3 + x + 1)
    M = MatrixSpace(F, 4, 4)
    MDS = M([
        [a^1,     a^1 + 1, 1,       1,],
        [1,       a^1,     a^1 + 1, 1,],
        [1,       1,       a^1,     a^1 + 1,],
        [a^1 + 1, 1,       1,       a^1,],
    ])
    print(MDS)
    print(MDS.inverse())

YEAH! because i don't know how to do it from scratch. now i run the code but using our current irreducible polynomial:

    F.<a> = GF(2^4, modulus=x^4 + x^3 + x^2 + x + 1)
    M = MatrixSpace(F, 2, 2)
    MDS = M([
        [a^1,     a^1 + 1,],
        [1,       a^1,],
    ])
    print(MDS)
    print(MDS.inverse())

and got this result:

    [a^3 + a^2 + 1           a^2]
    [      a^3 + 1 a^3 + a^2 + 1]

converting the result to decimal:

    [13, 4]
    [9, 13]

then the inverse mixcolumns MDS, based on aes mix column inverted with our irreducible polynomial, become:

    -------
    |13|4 |
    |9 |13|
    -------
