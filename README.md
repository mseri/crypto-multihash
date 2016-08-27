# Crypto Multihash

[![Build Status](https://travis-ci.org/mseri/crypto-multihash.svg?branch=master)](https://travis-ci.org/mseri/crypto-multihash)
[![Hackage](https://img.shields.io/hackage/v/crypto-multihash.svg)](http://hackage.haskell.org/package/crypto-multihash)
![Hackage Dependencies](https://img.shields.io/hackage-deps/v/crypto-multihash.svg)
![Haskell Programming Language](https://img.shields.io/badge/language-Haskell-blue.svg)
![BSD3 License](http://img.shields.io/badge/license-BSD3-brightgreen.svg)


Multihash library implemented on top of [cryptonite](https://hackage.haskell.org/package/cryptonite) cryptographic library. 
Multihash is a protocol for encoding the hash algorithm and digest length at the start of the digest, see the official [multihash github page](https://github.com/jbenet/multihash/).

This library is still experimental and the api is not guaranteed stable. 
I will increment the version number appropriately in case of breaking changes.

For the moment the library implements all the expected hashing algorithms with the exception of shake-128 and shake-256. A Multihash can be encoded in hex (`Base16`), base 32 (`Base32`), bitcoin base58 (`Base58`) and base64 (`Base64`). 

# Usage

```{.haskell}
-- in ghci `:set -XOverloadedStrings`
{-# LANGUAGE OverloadedStrings #-}

-- `:m +Crypto.Multihash`
import Crypto.Multihash
import Data.ByteString (ByteString)

main = do
    let v = "test"::ByteString
    let m = multihash SHA256 v

    -- If using the Weak module
    -- let m' = weakMultihash "sha256" v
    
    putStrLn $ "Base16: " ++ (encode' Base16 m)
    -- You might need to specify the encoded string type
    putStrLn $ "Base58: " ++ (encode' Base58 m :: String)

    -- `encode` is the safe interface returning an `Either` type
    putStrLn $ "Base64: " ++ show (encode Base64 m :: Either String String)
    
    let h = encode' Base58 m :: ByteString
    -- You can check that a multihash corresponds to some data `v`
    checkMultihash h v
    -- Right True
    
    -- Or if you have a Multihash to compare you can use it
    check h m
    -- Right True

    -- There is also an unsafe version, as for encode
    -- note that sometimes you will need to specify the string types
    checkMultihash' ("whatever"::String) v
    -- *** Exception: Unable to infer an encoding
    checkMultihash' ("Eiwhatever"::ByteString) v
    -- *** Exception: base64: input: invalid length
    check' ("EiCfhtCBiEx9ZZov6qDFWtAVo79PGysLgizRXWwVsPA1CA=="::ByteString) m
    -- False

    checkMultihash' h v
    -- True
    check' h m
    -- True
```

The of `import Crypto.Multihash.Weak` is almost identical, but it additionally introduces the function `toWeakMultihash` that tries to import a string as a `WeakMultihashDigest`.

# Test

Some preliminary tests can be performed with `stack test`. 

A simple example encoder is in `app/Main.hs`. 
You can run it on files

```{.bash}
echo -n test | stack exec mh -- somefile someotherfile
```

or read data from the standard input 

```{.bash}
echo -n test | stack exec mh -- -
```

# Contribution

1. Fork repository
2. Do some changes
3. Create pull request
4. Wait for CI build and review

You can use stack to build the project: `stack build`

To run tests: `stack test`

# TODO

- ~~Test the new `getBase` implementation using quickcheck~~
- Accurately test the correct support of truncated multihashes, including the truncation length that triggers easy failures in `getBase`
- Implement benchmarks, then start optimising the code where possible
- ~~Use the hash length in `checkPayload` to treat correctly truncated hashes (see https://github.com/jbenet/multihash/issues/1#issuecomment-91783612)~~
- Improve documentation
- Implement `shake-128` and `shake-256` multihashes
- ~~Implement `Base32` encoding~~ waiting for https://github.com/jbenet/multihash/issues/31 to be resolved)
