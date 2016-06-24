-- |
-- Module      : Crypto.Multihash.Weak
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
-- The 'Crypto.Multihash.Weak' module contains a weaker implementation of the
-- MultihashDigest type that allows to deserialize multihashes and to work with
-- different algorithms at the same type. The API interface is almost identical
-- to the one exposed by 'Crypto.Multihash'. The notable differences are:
-- 
--  - the hash algorithms is no longer a type 
--  - the type returned by the multihash constructors is an 'Either' 
--    (see 'weakMultihash' and 'weakMultihashlazy')
--  - there is a function 'toWeakMultihash' to deserialise multihashes
--
-- For additional informations refer to the README.md or the
-- <https://github.com/mseri/crypto-multihash gihub repository>.
--
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- TODO: use length in check* to treat correctly truncated hashes
-- see https://github.com/jbenet/multihash/issues/1#issuecomment-91783612

module Crypto.Multihash.Weak 
  ( -- * Weak Multihash Types
    WeakMultihashDigest
  , Base            (..)
  , Encodable       (..)
  --, Checkable       (..)
  --, Payload         (..)
    -- * Weak Multihash Helpers
  , weakMultihash
  , weakMultihash'
  , weakMultihashlazy
  , weakMultihashlazy'
  , toWeakMultihash
  , checkWeakMultihash
  , checkWeakMultihash'
  ) where

import Crypto.Hash (Digest, hashWith, hashlazy)
import qualified Crypto.Hash.Algorithms as A
import Data.ByteArray (ByteArrayAccess, Bytes)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.List (elemIndex)
import Data.String (IsString(..))
import Data.String.Conversions
import Data.Word (Word8)

-------------------------------------------------------------------------------
import Crypto.Multihash.Internal.Types
import Crypto.Multihash.Internal
-------------------------------------------------------------------------------

data HashAlgo = S1 A.SHA1 | S256 A.SHA256 | S512 A.SHA512 
              | S3_512 A.SHA3_512 | S3_384 A.SHA3_384
              | S3_256 A.SHA3_256 | S3_224 A.SHA3_224
              | B2s A.Blake2s_256 | B2b A.Blake2b_512

instance Eq HashAlgo where
  (S1 _)     == (S1 _)     = True 
  (S256 _)   == (S256 _)   = True
  (S512 _)   == (S512 _)   = True
  (S3_512 _) == (S3_512 _) = True
  (S3_384 _) == (S3_384 _) = True
  (S3_256 _) == (S3_256 _) = True
  (S3_224 _) == (S3_224 _) = True
  (B2s _)    == (B2s _)    = True
  (B2b _)    == (B2b _)    = True
  _          == _          = False

instance Show HashAlgo where
  show (S1 A.SHA1)         = "sha1"
  show (S256 A.SHA256)     = "sha256"
  show (S512 A.SHA512)     = "sha512"
  show (S3_512 A.SHA3_512) = "sha3-512"
  show (S3_384 A.SHA3_384) = "sha3-384"
  show (S3_256 A.SHA3_256) = "sha3-256"
  show (S3_224 A.SHA3_224) = "sha3-224"
  show (B2s A.Blake2s_256) = "blake2s-256"
  show (B2b A.Blake2b_512) = "blake2b-512"

instance Codable HashAlgo where
  toCode (S1 A.SHA1)         = 0x11
  toCode (S256 A.SHA256)     = 0x12
  toCode (S512 A.SHA512)     = 0x13
  toCode (S3_512 A.SHA3_512) = 0x14
  toCode (S3_384 A.SHA3_384) = 0x15
  toCode (S3_256 A.SHA3_256) = 0x16
  toCode (S3_224 A.SHA3_224) = 0x17
  toCode (B2b A.Blake2b_512) = 0x40
  toCode (B2s A.Blake2s_256) = 0x41

-------------------------------------------------------------------------------

-- | Weak Multihash Digest container
data WeakMultihashDigest = WeakMultihashDigest
  { _getAlgorithm :: HashAlgo      -- ^ hash algorithm encoded as int
  , _getLength    :: Int           -- ^ hash lenght
  , _getDigest    :: Bytes         -- ^ binary digest data
  } deriving (Eq)

instance Show WeakMultihashDigest where
  -- an error here should never happen
  show = encode' Base58

instance Encodable WeakMultihashDigest where
  encode base (WeakMultihashDigest alg len md) = 
    if len == BA.length md
      then do
        d <- fullDigestUnpacked
        return $ fromString $ map (toEnum . fromIntegral) d
      else 
        Left "Corrupted MultihashDigest: invalid length"
    where
      fullDigestUnpacked :: Either String [Word8]
      fullDigestUnpacked = do
        d <- encoder base fullDigest
        return $ BA.unpack d
      
      fullDigest :: Bytes
      fullDigest = BA.pack hd `BA.append` md
        where
          hd :: [Word8]
          hd = fromIntegral <$> [toCode alg, len]


  check hash_ multihash_ = let hash_' = convertString hash_ in do
    base <- getBase hash_'
    m <- encode base multihash_
    return (m == hash_')

-- | Newtype to allow the creation of a 'Checkable' typeclass for 
--   all 'ByteArrayAccess' without recurring to UndecidableInstances.
newtype Payload bs =  Payload bs

instance ByteArrayAccess bs => Checkable (Payload bs) where
  checkPayload hash_ (Payload p) = let hash' = convertString hash_ in do
    m <- toWeakMultihash hash'
    wmh <- weakMultihash (convertString $ show $ _getAlgorithm m) p
    check hash' wmh

-------------------------------------------------------------------------------

allowedAlgos :: [(ByteString, HashAlgo)]
allowedAlgos  = [ ("sha1", S1 A.SHA1) 
                , ("sha256", S256 A.SHA256)
                , ("sha512", S512 A.SHA512)
                , ("sha3-512", S3_512 A.SHA3_512)
                , ("sha3-384", S3_384 A.SHA3_384)
                , ("sha3-256", S3_256 A.SHA3_256)
                , ("sha3-224", S3_224 A.SHA3_224)
                , ("blake2b-512", B2b A.Blake2b_512)
                , ("blake2s-256", B2s A.Blake2s_256) ]

-- | Helper to multihash a 'ByteArrayAccess' (e.g. a 'BS.ByteString') using a 
--   supported hash algorithm. Uses 'Crypto.Hash.hash' for hashing.
weakMultihash :: ByteArrayAccess bs
                 => ByteString -> bs -> Either String WeakMultihashDigest
weakMultihash alg p = do
  alg' <- maybeToEither "Unknown algorithm" $ 
                        lookup (convertString alg) allowedAlgos
  let h = case alg' of
            S1 a     -> BA.convert $ hashWith a p
            S256 a   -> BA.convert $ hashWith a p
            S512 a   -> BA.convert $ hashWith a p
            S3_512 a -> BA.convert $ hashWith a p
            S3_384 a -> BA.convert $ hashWith a p
            S3_256 a -> BA.convert $ hashWith a p
            S3_224 a -> BA.convert $ hashWith a p
            B2b a    -> BA.convert $ hashWith a p
            B2s a    -> BA.convert $ hashWith a p
  return $ WeakMultihashDigest alg' (BA.length h) h

-- | Unsafe equivalent of 'weakMultihash'. Throws on creation errors.
weakMultihash' :: ByteArrayAccess bs => ByteString -> bs -> WeakMultihashDigest
weakMultihash' alg p = eitherToErr $ weakMultihash alg p

-- | Run the 'hashlazy' function but takes an explicit hash algorithm parameter
hashlazyWith :: A.HashAlgorithm alg => alg -> BL.ByteString -> Digest alg
hashlazyWith _ = hashlazy

-- | Helper to multihash a lazy 'BL.ByteString' using a supported hash algorithm.
--   Uses 'Crypto.Hash.hashlazy' for hashing.
weakMultihashlazy :: ByteString -> BL.ByteString -> Either String WeakMultihashDigest
weakMultihashlazy alg p = do
  alg' <- maybeToEither "Unknown algorithm" $ lookup alg allowedAlgos
  let h = case alg' of
            S1 a     -> BA.convert $ hashlazyWith a p
            S256 a   -> BA.convert $ hashlazyWith a p
            S512 a   -> BA.convert $ hashlazyWith a p
            S3_512 a -> BA.convert $ hashlazyWith a p
            S3_384 a -> BA.convert $ hashlazyWith a p
            S3_256 a -> BA.convert $ hashlazyWith a p
            S3_224 a -> BA.convert $ hashlazyWith a p
            B2b a    -> BA.convert $ hashlazyWith a p
            B2s a    -> BA.convert $ hashlazyWith a p
  return $ WeakMultihashDigest alg' (BA.length h) h

-- | Unsafe equivalent of 'weakMultihashlazy'. Throws on creation errors.
weakMultihashlazy' :: ByteString -> BL.ByteString -> WeakMultihashDigest
weakMultihashlazy' alg p = eitherToErr $ weakMultihashlazy alg p

-------------------------------------------------------------------------------

-- | Imports a multihash into a 'WeahMultihashDigest' if possible.
toWeakMultihash :: BS.ByteString  -> Either String WeakMultihashDigest
toWeakMultihash bs = do
    base <- getBase bs
    h <- convertFromBase base bs
    if badLength h 
      then 
        Left "Corrupted MultihasDigest: invalid length"
      else do
        [b, b'] <- return $ take 2 $ BA.unpack h
        case elemIndex b hashCodes of
          Just 0 -> d h b' $ S1 A.SHA1
          Just 1 -> d h b' $ S256 A.SHA256
          Just 2 -> d h b' $ S512 A.SHA512
          Just 3 -> d h b' $ S3_512 A.SHA3_512
          Just 4 -> d h b' $ S3_384 A.SHA3_384
          Just 5 -> d h b' $ S3_256 A.SHA3_256
          Just 6 -> d h b' $ S3_224 A.SHA3_224
          Just 7 -> d h b' $ B2b A.Blake2b_512
          Just 8 -> d h b' $ B2s A.Blake2s_256
          Just _ -> Left "This should be impossible"
          Nothing -> Left "Impossible to infer the appropriate hash from the header"
  where 
    d h b' alg = Right $ WeakMultihashDigest alg (fromIntegral b') 
                                             (BA.convert $ BA.drop 2 h)

-------------------------------------------------------------------------------

-- | 'checkPayload' wrapper for API retro-compatibility.
checkWeakMultihash :: (IsString s, ConvertibleStrings s BS.ByteString, ByteArrayAccess bs)
                  => s -> bs -> Either String Bool
checkWeakMultihash h p = checkPayload h (Payload p)

-- | Unsafe 'checkPayload' wrapper for API retro-compatibility.
checkWeakMultihash' :: (IsString s, ConvertibleStrings s BS.ByteString, ByteArrayAccess bs)
                   => s -> bs -> Bool
checkWeakMultihash' h p = checkPayload' h (Payload p)
