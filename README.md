# COMP6441-Project
This codebase includes an implementation of AES encryption and a CTR-DRBG (Counter-mode Deterministic Random Bit Generator) as specified in NIST SP 800-90A. It supports AES-128, AES-192, and AES-256 using single-block ECB encryption and can be used to generate secure pseudorandom data.

How to Use the AES Encryption:

The AES part of the code supports single-block encryption. You must provide:

A 16-byte plaintext block - you can only encode in 16 byte blocks.

A key of appropriate length (16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256)

To encrypt a block, use the aes_encrypt_block(plaintext, key) function.

An example is shown in the code as the function called example_aes.

How to Use the CTR-DRBG:

An example of how to use the CTR-DRBG is shown under the function example_drbg().

To instantiate the DRBG, you need to form the seed material by combining entropy input, and then optionally adding a nonce and/or personalization string.
Then you set V and Key to zero with the appropriate size where V is 16 bytes and key is keylen bytes (keylen depends on what implementation of the AES you choose to use where 16 is AES-128, 24 is AES-192 and 32 is AES-256).

Then you call drbg_update with the seed, a zero key, a zero V and the key length to instantiate the drbg.

To generate the first set of random bits you call drbg_generate with your key, V, number of requested bits and key length.
drbg_generate(Key, V, 64, keylen)

If you also want to provide additional inputs to the generate call you can use the function:
drbg_generate(Key, V, 64, keylen, additional_input)

After the generate call for the first time it is recommended/common from NIST to ignore the first result. This is done in some NIST test vectors where the first output is not checked. 

For the second generate call, you can set the result to a specific variable such as the one below to find the random bytes requested.
random_bytes, Key, V = drbg_generate(Key, V, 32, keylen)

Reseeding

You can reseed the DRBG using new entropy input and optional additional input:

Key, V = drbg_reseed(new_entropy, additional_input, Key, V, keylen)


