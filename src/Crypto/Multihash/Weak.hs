{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- TODO: decide if it is better to move the MultihashDigest a and Payload a
-- here to remove the orphan istance warning
{-# OPTIONS_GHC -fno-warn-orphans #-}

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

import Data.ByteArray (ByteArrayAccess, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base58 as B58
import Data.String (IsString(..))
import Data.String.Conversions

import Crypto.Multihash.Internal.Types
import Crypto.Multihash.Internal

weakAlgos = [ "sha1", "sha256", "sha512", "sha3-512" 
                , "sha3-384", "sha3-256", "sha3-224"
                , "blake2b-512", "blake2s-256" ]

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