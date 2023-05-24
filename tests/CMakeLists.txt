
add_executable(test_aes test_aes.c)
target_link_libraries(test_aes zcrypto)

add_executable(test_base64 test_base64.c)
target_link_libraries(test_base64 zcrypto)

add_executable(test_hash test_hash.c)
target_link_libraries(test_hash zcrypto)

add_executable(test_oaep test_oaep.c)
target_link_libraries(test_oaep zcrypto)

add_executable(test_rsa test_rsa.c)
target_link_libraries(test_rsa zcrypto)

add_executable(test_sm4 test_sm4.c)
target_link_libraries(test_sm4 zcrypto)

