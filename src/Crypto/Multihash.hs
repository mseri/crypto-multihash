-- |
-- Module      : Crypto.Multihash
-- License     : BSD3
-- Maintainer  : Marcello Seri <marcello.seri@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Multihash library built on top of haskell 'cryptonite' crypto package
-- Multihash is a protocol for encoding the hash algorithm and digest length 
-- at the start of the digest, see the official 
-- <https://github.com/jbenet/multihash/ multihash poroposal github repo>.
--
-- The library re-exports the needed types and typclasses from 'Crypto.Hash.Algorithms'
-- namely 'HashAlgorithm', 'SHA1', 'SHA256', 'SHA512', 'SHA3_512', 'SHA3_384',
-- 'SHA3_256', 'SHA3_224', 'Blake2b_512', 'Blake2s_256'. 
--
-- For additional informations refer to the README.md or the
-- <https://github.com/mseri/crypto-multihash gihub repository>.
--
{-# LANGUAGE OverloadedStrings #-}

module Crypto.Multihash
  ( -- * Multihash Types
    MultihashDigest
  , Base            (..)
  , Codable         (..)
  -- * Multihash helpers
  , encode
  , encode'
  , multihash
  , multihashlazy
  , checkMultihash
  , checkMultihash'
  -- * Re-exported types
  , HashAlgorithm
  , SHA1(..)
  , SHA256(..)
  , SHA512(..)
  , SHA3_512(..)
  , SHA3_384(..)
  , SHA3_256(..)
  , SHA3_224(..)
  , Blake2b_512(..)
  , Blake2s_256(..)
  ) where

import Crypto.Hash (Digest, hash, hashlazy)
import Crypto.Hash.Algorithms
--import Crypto.Hash.IO
import Data.ByteArray (ByteArrayAccess, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base58 as B58
import Data.List (elemIndex)
import Data.String (IsString(..))
import Data.Word (Word8)
import Text.Printf (printf)

-- | 'Base' usable to encode the digest 
data Base = Base2   -- ^ Binary form
          | Base16  -- ^ Hex encoding
          | Base32  -- ^ Not yet implemented. Waiting for <https://github.com/jbenet/multihash/issues/31 this issue to resolve>
          | Base58  -- ^ Bitcoin base58 encoding
          | Base64  -- ^ Base64 encoding
          deriving (Show, Eq)

-- | Multihash Digest container
data MultihashDigest a = MultihashDigest
  { getAlgorithm :: a     -- ^ hash algorithm
  , getLength :: Int      -- ^ hash lenght
  , getDigest :: Digest a -- ^ binary digest data
  } deriving (Eq)

-- | 'Codable' hash algorithms are the algorithms supported for multihashing
class Codable a where
  -- | Returns the first byte for the head of the multihash digest
  toCode :: a -> Int

instance Codable SHA1 where
  toCode SHA1 = 0x11
instance Codable SHA256 where
  toCode SHA256 = 0x12
instance Codable SHA512 where
  toCode SHA512 = 0x13
instance Codable SHA3_512 where
  toCode SHA3_512 = 0x14
instance Codable SHA3_384 where
  toCode SHA3_384 = 0x15
instance Codable SHA3_256 where
  toCode SHA3_256 = 0x16
instance Codable SHA3_224 where
  toCode SHA3_224 = 0x17
instance Codable Blake2b_512 where
  toCode Blake2b_512 = 0x40
instance Codable Blake2s_256 where
  toCode Blake2s_256 = 0x41

-- TODO: add shake-128/256 to Codable. Probably
-- fromCode 0x18 = Keccak_256
-- fromCode 0x19 = Keccak_512

instance Show (MultihashDigest a) where
    show (MultihashDigest _ _ d) = show d

-- | Helper to multihash a lazy 'BL.ByteString' using a supported hash algorithm.
--   Uses 'Crypto.Hash.hashlazy' for hashing.
multihashlazy :: (HashAlgorithm a, Codable a) => a -> BL.ByteString -> MultihashDigest a
multihashlazy alg bs = let digest = hashlazy bs
                       in MultihashDigest alg (BA.length digest) digest

-- | Helper to multihash a 'ByteArrayAccess' (e.g. a 'BS.ByteString') using a 
--   supported hash algorithm. Uses 'Crypto.Hash.hash' for hashing.
multihash :: (HashAlgorithm a, Codable a, ByteArrayAccess bs) => a -> bs -> MultihashDigest a
multihash alg bs = let digest = hash bs
                   in MultihashDigest alg (BA.length digest) digest


-- | Safe encoder for 'MultihashDigest'.
encode :: (HashAlgorithm a, Codable a, Show a, IsString s) => 
          Base -> MultihashDigest a -> Either String s
encode base (MultihashDigest alg len md) = 
  if len == BA.length md
    then do
      d <- fullDigestUnpacked
      return $ fromString $ map (toEnum . fromIntegral) d
    else 
      Left $ printf "Corrupted %s MultihashDigest: invalid length" (show alg)

  where
    fullDigestUnpacked :: Either String [Word8]
    fullDigestUnpacked = do
      d <- encoder fullDigest
      return $ BA.unpack d
      where 
        encoder :: ByteArrayAccess a => a -> Either String Bytes
        encoder bs = case base of
                    Base2  -> return $ BA.convert bs
                    Base16 -> return $ BE.convertToBase BE.Base16 bs
                    Base32 -> Left "Base32 encoder not implemented"
                    Base58 -> return $ BA.convert $ B58.encodeBase58 B58.bitcoinAlphabet 
                                                                     (BA.convert bs :: BS.ByteString)
                    Base64 -> return $ BE.convertToBase BE.Base64 bs

    fullDigest :: Bytes
    fullDigest = BA.pack [dHead, dSize] `BA.append` dTail
      where
        dHead :: Word8
        dHead = fromIntegral $ toCode alg
        dSize :: Word8
        dSize = fromIntegral len
        dTail :: Bytes
        dTail = BA.convert md

-- | Unsafe encoder for 'MultihashDigest'.
--   Throws an error if there are encoding issues or the 'MultihashDigest'
--   length field does not match the 'Digest' length.
encode' :: (HashAlgorithm a, Codable a, Show a, IsString s) 
           => Base -> MultihashDigest a -> s
encode' base md = 
  case encode base md of
    Right enc -> enc
    Left err  -> error err

-- TODO: use length in checkMultihash to treat correctly truncated hashes
-- see https://github.com/jbenet/multihash/issues/1#issuecomment-91783612

-- | Safely check the correctness of an encoded 'MultihashDigest' against the 
--   corresponding data. Tha data is passed as a 'ByteArrayAccess' 
--   (e.g. a 'BS.BinaryString').
checkMultihash :: ByteArrayAccess bs => BS.ByteString -> bs -> Either String Bool
checkMultihash hash unahshedData = do
  base <- getBase hash
  mhd <- convertFromBase base hash
  -- Hacky... think to a different approach
  if badLength mhd 
    then 
      Left "Corrupted MultihasDigest: invalid length"
    else do
      m <- getBinaryEncodedMultihash mhd unahshedData
      return (C.pack m == mhd)

-- | Unsafe version of 'checkMultihash'. Throws on encoding/decoding errors 
--   instead of returning an 'Either' type. 
checkMultihash' :: ByteArrayAccess bs => BS.ByteString -> bs -> Bool
checkMultihash' hash unahshedData = 
  case checkMultihash hash unahshedData of
    Right ans -> ans
    Left err  -> error err

-- Helpers - These are not exported currently, and probably will never be.

maybeToEither :: l -> Maybe r -> Either l r
maybeToEither _ (Just res) = Right res
maybeToEither err _        = Left err

-- | Convert a 'BS.ByteString' from a 'Base' into a 'BS.BinaryString' in 'Base2'.
convertFromBase :: Base -> BS.ByteString -> Either String BS.ByteString
convertFromBase b bs = case b of
  Base2  -> Left "This is not supposed to happen"
  Base16 -> BE.convertFromBase BE.Base16 bs
  Base32 -> Left "Base32 decoder not implemented"
  Base58 -> do
    dec <- maybeToEither "Base58 decoding error" (B58.decodeBase58 B58.bitcoinAlphabet bs)
    return (BA.convert dec)
  Base64 -> BE.convertFromBase BE.Base64 bs

-- | Infer the 'Base' encoding function from an encoded 'BS.BinaryString' representing 
-- a 'MultihashDigest'.
getBase :: BS.ByteString -> Either String Base
getBase h
      | startWiths h ["1114", "1220", "1340", "1440", "1530", "1620", "171c", "4040", "4120"] = Right Base16
      | startWiths h ["5d", "Qm", "8V", "8t", "G9", "W1", "5d", "S2", "2U"] = Right Base58
      | startWiths h ["ER", "Ei", "E0", "FE", "FT", "Fi", "Fx", "QE", "QS"] = Right Base64
      | otherwise = Left "Unable to infer an encoding"
      where startWiths h = any (`BS.isPrefixOf` h)

-- | Compares the lenght of the encoded 'MultihashDigest' with the encoded hash length.
--   Returns 'True' if the lengths are matching.
badLength :: ByteArrayAccess bs => bs -> Bool
badLength mh = 
      case BA.length mh of
        n | n <= 2 -> True
        n | BA.index mh 1 /= (fromIntegral n-2) -> True
        _ -> False

-- | Infer the hash function from an unencoded 'BS.BinaryString' representing 
--   a 'MultihashDigest' and uses it to binary encode the data in a 'MultihashDigest'.
getBinaryEncodedMultihash :: (ByteArrayAccess bs, IsString s) => BS.ByteString -> bs -> Either String s
getBinaryEncodedMultihash mhd uh = let bitOne = head $ BS.unpack mhd in
  case elemIndex bitOne hashCodes of
    Just 0 -> rs SHA1 uh
    Just 1 -> rs SHA256 uh
    Just 2 -> rs SHA512 uh
    Just 3 -> rs SHA3_512 uh
    Just 4 -> rs SHA3_384 uh
    Just 5 -> rs SHA3_256 uh
    Just 6 -> rs SHA3_224 uh
    Just 7 -> rs Blake2b_512 uh
    Just 8 -> rs Blake2s_256 uh
    Just _ -> Left "This should be impossible"
    Nothing -> Left "Impossible to infer the appropriate hash from the header"
  where 
    rs alg = encode Base2 . multihash alg
    hashCodes :: [Word8]
    hashCodes = map fromIntegral
                    ([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x40, 0x41]::[Int])
