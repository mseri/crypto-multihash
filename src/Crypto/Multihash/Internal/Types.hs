{-# LANGUAGE FlexibleContexts #-}
module Crypto.Multihash.Internal.Types where

import Crypto.Hash.Algorithms
import Data.ByteString (ByteString)
import Data.String (IsString(..))
import Data.String.Conversions

-- | 'Base' usable to encode the digest 
data Base = Base2   -- ^ Binary form
          | Base16  -- ^ Hex encoding
          | Base32  -- ^ Not yet implemented. Waiting for <https://github.com/jbenet/multihash/issues/31 this issue to resolve>
          | Base58  -- ^ Bitcoin base58 encoding
          | Base64  -- ^ Base64 encoding
          deriving (Eq, Show)

-- | 'Codable' hash algorithms are the algorithms supported for multihashing
class Codable a where
  -- | Returns the first byte for the head of the multihash digest
  toCode :: a -> Int

class Encodable a where
  -- | Safe encoder for 'Encodable'.
  encode :: IsString s => Base -> a -> Either String s
  -- | Unsafe encoder for 'Encodable'.
  --   Throws an error if there are encoding issues.
  encode' :: IsString s => Base -> a -> s
  encode' base digest = fromString <$> eitherToErr $ encode base digest

  -- | Safely check the correctness of an encoded 'Encodable' against a plain
  --   'Encodable'.
  check :: (IsString s, ConvertibleStrings s ByteString) => s -> a -> Either String Bool
  -- | Unsafe version of 'check'. Throws on encoding/decoding errors instead of returning an Either type.
  check' :: (IsString s, ConvertibleStrings s ByteString) => s -> a -> Bool
  check' encoded digest = eitherToErr $ check encoded digest

class Checkable b where
  -- | Safely check the correctness of an encoded 'Encodable' against the 
  --   corresponding data.
  checkPayload :: (IsString s, ConvertibleStrings s ByteString) => s -> b -> Either String Bool
  -- | Unsafe version of 'checkPayload'. 
  --   Throws on encoding/decoding errors instead of returning an 'Either' type.
  checkPayload' :: (IsString s, ConvertibleStrings s ByteString) => s -> b -> Bool
  checkPayload' encoded payload = eitherToErr $ checkPayload encoded payload

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

eitherToErr :: Either String b -> b
eitherToErr v = case v of
  Right val -> val
  Left  err -> error err
