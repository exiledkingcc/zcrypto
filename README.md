# zcrypto
a minimal crypto lib for limited environment like MCU.

*features*:
* base64
* hash
    * SM3
    * MD5
    * SHA1
    * SHA256
* block cipher algorithm
    * AES(128, 192, 256)
    * SM4
* block cipher mode
    * ECB
    * CBC
    * CFB
    * OFB
* asymmetric key encryption
    * RSA(2048)

## block cipher
* crypto algorithm:
    * AES(128, 192, 256)
    * SM4
* operation mode:
    * ECB
    * CBC
    * CFB
    * OFB

api has two styles:
* `aes_{keylen}_{mode}_{en/de}crypt` / `sm4_{mode}_{en/de}crypt`
* `aes_{en/de}crypt(aes_ctx_t*, ...)` / `sm4_{en/de}crypt(sm4_ctx_t*, ...)`

the first style api do **only once** encryption or decryption. but for the second style api,
you can call `{aes/sm4}_{en/de}crypt` multiple times and to encryption(decryption) for stream data.

for both two style apis, you should do the padding yourself, and make sure the input data length
**exactly** multiple of the block size (aka 16bytes).

see `test/test_{aes/sm4}.c` for details.

## hash
* SM3
* MD5
* SHA1
* SHA256
* HMAC(*TODO*)

how to use:
* use `{alg}_init` to initialize context.
* use `{alg}_update` to feed data.
* use `{alg}_[hex]digest` to get hash output.

you can call `{alg}_[hex]digest` whenever you like to get the hash of *current feeded data*,
then feed more data. but you should make sure the output has enough size for the hash result.

see `test/test_hash.c` for details.

## asymmetric key encryption

* RSA (2048)

Do **NOT** support private key. it's designed to keep key just in the code or somewhere easy to read, so you should **NOT** use private key there.

use `rsa_pub_naive` for RSA pulic key enrypt/decrypt. see `test/test_rsa.c` for how to use. use `rsa_pub_naive./test/rsa_naive_test.py | ./build/test_rsa.elf` for test.

use `rsa_pub_oaep_encrypt` for `RSAES-OAEP` operation，see [RFC8017](https://tools.ietf.org/html/rfc8017#section-7.1) for reference. see `test/test_oaep.c` for how to use. use `./test/rsa_oaep_test.py gen | ./build/test_oaep.elf | ./test/rsa_oaep_test.py verify` for test.
