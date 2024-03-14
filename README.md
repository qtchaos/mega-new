# mega-login

A WIP project that creates & verifies mega.nz accounts by directly interacting with the mega.nz API.

There is most liekly some issues with the key generation part of the code, due to the original source using `asmCrypto` and `msCrypto` which are not available in node. I tried my best to port the code but encountered some differences which will probably still need to be resolved. (which SHA is being used, RSAES-PKCS1-v1_5 vs RSASSA-PKCS1-v1_5)

## Status
 - [x] Send verification email
 - [x] Get verification code
 - [x] Set up keys & bind to account (sort of)
    - We send the keys to the server, but RSA error on login probably due to authring not being set up. (or keys not being set up properly)
 - [] Authring 
 - [] Able to login to account
