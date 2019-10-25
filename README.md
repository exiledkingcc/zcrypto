# zcrypto
a minimal crypto lib for limited environment like STM32.

---
一个为受限环境（比如STM32）写的加密相关操作的库。

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
* `cipher_init` / `cipher_operate`

the first style api do **only once** encryption or decryption. but for the second style api, you can call `cipher_operate` multiple times and to encryption(decryption) for stream data.

for both two style apis, you should do the padding your self, and make sure the input data length **exactly queals to** the block size (aka 16bytes).

see test.c for details.

---
**分组密码**

支持：AES（192、169，256）， SM4，模式支持ECB，CBC，CFB，OFB。
支持两种风格的API。一种是：`aes_{keylen}_{mode}_{en/de}crypt`和`sm4_{mode}_{en/de}crypt`，这是做一次性加密（解密）的。另一种是`cipher_init`和`cipher_operate`，这个`cipher_operate`可以调用多次，对流数据进行加密（解密）。具体使用请看`test.c`。

## hash
* SM3
* MD5
* SHA1(*TODO*)
* SHA256(*TODO*)
* HMAC(*TODO*)

how to use:
* use `{alg}_init` to initialize context.
* use `{alg}_update` to feed data.
* use `{alg}_[hex]digest` to get hash output.

you can call `{alg}_[hex]digest` whenever you like to get the hash of *current feeded data*, then feed more data. but you should make sure the output has enough size for the hash result.

see test.c for details.

---
**HASH算法**

支持SM3，MD5，计算支持SHA1，SHA256与HMAC。使用`{alg}_init`初始化，使用`{alg}_update`更新数据，使用`{alg}_[hex]digest`输出hash值。可以在任意时候调用`{alg}_[hex]digest`获取当前数据的hash值。但是需要保证结果的空间足够存hash值。具体使用请看test.c。

## asymmetric key encryption
*maybe, no plan for now*
