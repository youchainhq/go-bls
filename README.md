# go-bls

Go implementation of BLS (Boneh-Lynn-Shacham) signatures, currently only support the BLS12-381 curve (Barreto-Lynn-Scott). 

Currently it's just a wrap of the pure go project [phoreproject/bls](https://github.com/phoreproject/bls) for the needs of the go-youchain.

## Notice

This project will stick to a `minimizing signature size` scheme, that is: put signatures in G1 and public keys in G2, where G1/E1 has the more compact representation.
