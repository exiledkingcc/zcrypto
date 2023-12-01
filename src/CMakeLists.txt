
set(sources
    aes.c
    base64.c
    hash.c
    hashlib.c
    md5.c
    oaep.c
    rsa.c
    sha1.c
    sha256.c
    sm3.c
    sm4.c
)

add_library(zcrypto STATIC ${sources})
