{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Multihash
import Data.ByteString hiding (putStrLn)

printer :: (HashAlgorithm a, Codable a, Show a) => a -> IO ()
printer ha = do
  let m = multihash ha ("test"::ByteString)
  putStrLn $ "Hashing \"test\" with " ++ (show ha)
  putStrLn $ "Base16: " ++ (encode Base16 m)
  -- Base32 missing
  putStrLn $ "Base58: " ++ (encode Base58 m)
  putStrLn $ "Base64: " ++ (encode Base64 m)
  putStrLn ""


main :: IO ()
main = do
  printer SHA1
  printer SHA256
  printer SHA512
  printer SHA3_512
  printer SHA3_384
  printer SHA3_256
  printer SHA3_224
  printer Blake2b_512
  printer Blake2s_256
  putStrLn "Done! Note: shake-128/256 and Base32 are missing"