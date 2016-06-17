module Crypto.Multihash
  ( MultihashDigest
  , Base            (..)
  , Codable         (..)
  , HashAlgorithm   (..)
  , SHA1(..)
  , SHA256(..)
  , SHA512(..)
  , SHA3_512(..)
  , SHA3_384(..)
  , SHA3_256(..)
  , SHA3_224(..)
  , Blake2b_512(..)
  , Blake2s_256(..)
  , encode
  , multihash
  , multihashlazy
  ) where

import Crypto.Hash (HashAlgorithm(..), Digest(..), hash, hashlazy)
import Crypto.Hash.Algorithms
import Crypto.Hash.IO
import Data.ByteArray (ByteArrayAccess, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base58 as B58
import Data.Word (Word8)
import Text.Printf (printf)

data Base = Base16  -- ^ Hex encoding
          | Base32  -- ^ Not implemented. For reasons that I did not investigate, the instance in Data.ByteArray produces output not conformant with the multihash spec.
          | Base58  -- ^ Bitcoin Base58 encoding, the one used also by IPFS
          | Base64  -- ^ Base64 encoding
          deriving (Eq)

-- | Multihash Digest container
data MultihashDigest a = MultihashDigest
  { getAlgorithm :: a
  , getLength :: Int
  , getDigest :: Digest a
  }

class Codable a where
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

multihashlazy :: (HashAlgorithm a, Codable a) => a -> BL.ByteString -> MultihashDigest a
multihashlazy alg bs = let digest = (hashlazy bs) 
                       in MultihashDigest alg (BA.length digest) digest

multihash :: (HashAlgorithm a, Codable a, ByteArrayAccess bs) => a -> bs -> MultihashDigest a
multihash alg bs = let digest = (hash bs) 
                   in MultihashDigest alg (BA.length digest) digest

-- | Encoder for 'Multihash'es.
--   Throws an error if the Multihash length field does not match the Digest length
encode :: (HashAlgorithm a, Codable a, Show a) => Base -> MultihashDigest a -> String
encode base (MultihashDigest alg len md) = if len == len'
    then map (toEnum . fromIntegral) fullDigestUnpacked
    else error $ printf "Corrupted %s MultihashDigest. Lenght is %d but should be %d." (show alg) len len'
  where
    len' :: Int
    len' = BA.length md

    fullDigestUnpacked :: [Word8]
    fullDigestUnpacked = BA.unpack $ encoder fullDigest
      where 
        encoder :: ByteArrayAccess a => a -> Bytes
        encoder bs = case base of
                    --Base2  -> BA.convert $ bs
                    Base16 -> BE.convertToBase BE.Base16 bs
                    Base32 -> error "Base32 encoder not implemented"
                    Base58 -> BA.convert $ B58.encodeBase58 B58.bitcoinAlphabet $ (BA.convert bs :: BS.ByteString)
                    Base64 -> BE.convertToBase BE.Base64 bs

    fullDigest :: Bytes
    fullDigest = BA.pack [dHead, dSize] `BA.append` dTail
      where
        dHead :: Word8
        dHead = fromIntegral $ toCode alg
        dSize :: Word8
        dSize = fromIntegral $ len'
        dTail :: Bytes
        dTail = BA.convert md

--checkHash :: Base -> String -> 

-- data MultihashAlgorithm = S1 SHA1 | S256 SHA256 | S512 SHA512 
--                         | S3512 SHA3_512 | S3384 SHA3_384 | S3256 SHA3_256 | S3224 SHA3_224
--                         | B2b Blake2b_512 | B2s Blake2s_256

-- toCode :: MultihashAlgorithm -> Int
-- toCode (S1 SHA1)        = 0x11
-- toCode (S256 SHA256)      = 0x12
-- toCode (S512 SHA512)      = 0x13
-- toCode (S3512 SHA3_512)    = 0x14
-- toCode (S3384 SHA3_384)    = 0x15
-- toCode (S3256 SHA3_256)    = 0x16
-- toCode (S3224 SHA3_224)    = 0x17
-- toCode (B2b Blake2b_512) = 0x40
-- toCode (B2s Blake2s_256) = 0x41
-- toCode _           = error "Multihash: unknown or unimplemented hash function code"