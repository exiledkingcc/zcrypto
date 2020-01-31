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

the first style api do **only once** encryption or decryption. but for the second style api,
you can call `cipher_operate` multiple times and to encryption(decryption) for stream data.

for both two style apis, you should do the padding your self, and make sure the input data length
**exactly queals to** the block size (aka 16bytes).

see `test/test_cipher.c` for details.

---
**分组密码**

支持：AES（192、169，256）， SM4，模式支持ECB，CBC，CFB，OFB。
支持两种风格的API。一种是：`aes_{keylen}_{mode}_{en/de}crypt`和`sm4_{mode}_{en/de}crypt`，
这是做一次性加密（解密）的。另一种是`cipher_init`和`cipher_operate`，这个`cipher_operate`可以调用多次，
对流数据进行加密（解密）。具体使用请看`test/test_cipher.c`。

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

---
**HASH算法**

支持SM3，MD5，SHA1，SHA256。使用`{alg}_init`初始化，使用`{alg}_update`更新数据，使用`{alg}_[hex]digest`输出hash值。
可以在任意时候调用`{alg}_[hex]digest`获取当前数据的hash值。但是需要保证结果的空间足够存hash值。具体使用请看`test/test_hash.c`。

## asymmetric key encryption

* RSA (2048)

Do **NOT** support private key. it's designed to keep key just in the code or somewhere easy to read, so you should **NOT** use private key there.

use `rsa_pub_naive` for RSA pulic key enrypt/decrypt. see `test/test_rsa.c` for details.

*TODO： OAEP padding*

---
**非对称密钥算法**

支持`RSA`（2048）。不支持私钥（其实支持私钥也很简单，毕竟运算是一样的）。
因为这个库的设计是，把密钥直接写在代码里面，或者很简单读取（无法保密），因此这里不能够使用私钥。

使用`rsa_pub_naive`进行公钥的运算，具体使用请看`test/test_rsa.c`。
使用`./test/rsa_naive_test.py | ./build/test_rsa.elf`进行测试。
