# Note on Used Irreducible Polynomial

data is in 2 bytes (16 bit). each cell in the state array is a nibble (4 bit).

Irreducible polynomials in GF(2^n)? Confusing lmao. I am not used to it. So? I just search paper that has irreducible polynomials in GF(2^4). here is the paper:

(
    http://ceser.in/ceserp/index.php/ijts/article/view/6021
    '4-bit crypto S-boxes: Generation with irreducible
    polynomials over Galois field GF(24) and cryptanalysis.'
    by Sankhanil Dey, Amlan Chakrabarti, Ranjan Ghosh
)

based on the paper, irreducible polynomials that is in GF(2^4) is:

    x^4 + x + 1             = 19 (decimal equivalent)
    x^4 + x^3 + 1           = 25 (decimal equivalent)
    x^4 + x^3 + x^2 + x + 1 = 31 (decimal equivalent)

From NIST FIPS 197, the AES irreducible polynomial is:

    m(x) = x^8 + x^4 + x^3 + x + 1

For this project's implementation, i decided to choose this irreducible polynomial:

    m(x) = x^4 + x^3 + x^2 + x + 1

(
    i just find the polynomial neat. `0b11111`, look at that! all 1.
)
