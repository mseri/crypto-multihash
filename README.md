# Crypto Multihash

![Hackage](https://img.shields.io/hackage/v/crypto-multihash.svg)
![Hackage Dependencies](https://img.shields.io/hackage-deps/v/crypto-multihash.svg)
![Haskell Programming Language](https://img.shields.io/badge/language-Haskell-blue.svg)
![BSD3 License](http://img.shields.io/badge/license-BSD3-brightgreen.svg)


Multihash library implemented on top of [cryptonite](https://hackage.haskell.org/package/cryptonite) cryptographic library. 
Multihash is a protocol for encoding the hash algorithm and digest length at the start of the digest, see the official [multihash github page](https://github.com/jbenet/multihash/).

This library is still experimental and the api is not guaranteed stable. 
I will increment the version number appropriately in case of breaking changes.

For the moment the library implements all the expected hashing algorithms with the exception of shake-128 and shake-256. A Multihash can be encoded in hex (`Base16`), bitcoin base58 (`Base58`) and base64 (`Base64`). 

The `Base32` encoding is not yet supported due to discrepancy between the encoding from `Data.ByteArray.Encoding` and the one appearing in the official multihash page.

# Usage

```{.haskell}
{-# LANGUAGE OverloadedStrings #-}

import Crypto.Multihash
import Data.ByteString (ByteString)

main = do
    let m = multihash SHA256 ("test"::ByteString)
    putStrLn $ "Base16: " ++ (encode Base16 m)
    putStrLn $ "Base58: " ++ (encode Base58 m)
    putStrLn $ "Base64: " ++ (encode Base64 m)
```

# Test

Some preliminary tests can be performed with `stack test`. 

A simple example encoder is in `app/Main.hs`. 
You can run it on files

```{.bash}
    echo -n test | stack exec mh -- somefile someotherfile
```

or read data from the standard input 

```{.bash}
echo -n test | stack exec mh -- -`
```

# Contribution

1. Fork repository
2. Do some changes
3. Create pull request
4. Wait for CI build and review

You can use stack to build the project: `stack build`

To run tests: `stack test`

# TODO

- Improve documentation
- Implement hash checker that takes some data and an encoded multihash and check that the multihash corresponds to the data (inferring automatically the appropriate hash function)
- Evaluate if throwing an error in the encode function is the wanted behaviour and anyway implement a safe version returning an Either type
- Implement `shake-128` and `shake-256` multihashes
- Implement `Base32` encoding