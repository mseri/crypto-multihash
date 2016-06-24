{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Crypto.Multihash.Weak 
  ( -- * Weak Multihash Types
    WeakMultihashDigest
  , Base            (..)
  , Encodable       (..)
  , Checkable       (..)
  , Payload         (..)
    -- * Weak Multihash Helpers
  , weakMultihash
  , weakMultihashlazy
  , toWeakMultihash
  , checkWeakMultihash
  , checkWeakMultihash'
  ) where

import Crypto.Hash (Digest, hash, hashlazy)
import qualified Crypto.Hash.Algorithms as A
import Data.ByteArray (ByteArrayAccess, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base58 as B58
import Data.String (IsString(..))
import Data.String.Conversions

import Crypto.Multihash.Internal.Types
import Crypto.Multihash.Internal

data HashAlgo = S1 A.SHA1 | S256 A.SHA256 | S512 A.SHA512 
              | S3_512 A.SHA3_512 | S3_384 A.SHA3_384
              | S3_256 A.SHA3_256 | S3_224 A.SHA3_224
              | B2s A.Blake2s_256 | B2b A.Blake2b_512

instance Show HashAlgo where
  show (S1 A.SHA1) = "sha1"
  show (S256 A.SHA256) = "sha256"
  show (S512 A.SHA512) = "sha512"
  show (S3_512 A.SHA3_512) = "sha3-512"
  show (S3_384 A.SHA3_384) = "sha3-384"
  show (S3_256 A.SHA3_256) = "sha3-256"
  show (S3_224 A.SHA3_224) = "sha3-224"
  show (B2s A.Blake2s_256) = "blake2s-256"
  show (B2b A.Blake2b_512) = "blake2b-512"

-- | Weak Multihash Digest container
data WeakMultihashDigest = WeakMultihashDigest
  { getAlgorithm :: HashAlgo      -- ^ hash algorithm encoded as int
  , getLength    :: Int           -- ^ hash lenght
  , getDigest    :: ByteString    -- ^ binary digest data
  } deriving (Eq)

instance Show WeakMultihashDigest where
  -- the error here should never happen
  show (WeakMultihashDigest _ _ d) = map (toEnum . fromIntegral) 
                                         (BA.unpack $ (BE.convertToBase BE.Base16 d :: ByteString))

allowedAlgos  = [ ("sha1", S1 A.SHA1) 
                , ("sha256", S256 A.SHA256)
                , ("sha512", S512 A.SHA512)
                , ("sha3-512", S3_512 A.SHA3_512)
                , ("sha3-384", S3_384 A.SHA3_384)
                , ("sha3-256", S3_256 A.SHA3_256)
                , ("sha3-224", S3_224 A.SHA3_224)
                , ("blake2b-512", B2b A.Blake2b_512)
                , ("blake2s-256", B2s A.Blake2s_256) ]

weakMultihash :: (ConvertibleStrings s BS.ByteString, ByteArrayAccess bs) 
                 => s -> bs -> WeakMultihashDigest
weakMultihash = undefined
weakMultihashlazy :: ConvertibleStrings s BS.ByteString 
                     => s -> BL.ByteString -> WeakMultihashDigest
weakMultihashlazy = undefined

toWeakMultihash :: ConvertibleStrings s BS.ByteString 
                     => s -> WeakMultihashDigest
toWeakMultihash = undefined

instance Encodable WeakMultihashDigest where
  encode base (WeakMultihashDigest alg len md) = undefined

  check hash_ multihash_ = let hash_' = convertString hash_ in do
    base <- getBase hash_'
    m <- encode base multihash_
    return (m == hash_')

-- | Newtype to allow the creation of a 'Checkable' typeclass for 
--   all 'ByteArrayAccess' without recurring to UndecidableInstances
newtype Payload bs =  Payload bs

instance ByteArrayAccess bs => Checkable (Payload bs) where
  checkPayload hash_ (Payload p) = undefined

-- | Alias for API retro-compatibility
checkWeakMultihash :: (IsString s, ConvertibleStrings s BS.ByteString, ByteArrayAccess bs)
                  => s -> bs -> Either String Bool
checkWeakMultihash h p = checkPayload h (Payload p)
-- | Alias for API retro-compatibility
checkWeakMultihash' :: (IsString s, ConvertibleStrings s BS.ByteString, ByteArrayAccess bs)
                   => s -> bs -> Bool
checkWeakMultihash' h p = checkPayload' h (Payload p)