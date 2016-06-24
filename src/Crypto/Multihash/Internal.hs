-- |
-- Module      : Crypto.Multihash.Internal
-- License     : BSD3
-- Maintainer  : Marcello Seri <marcello.seri@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.Multihash.Internal where

import Data.ByteArray (ByteArrayAccess(..))
import qualified Data.ByteArray as BA
import qualified Data.ByteArray.Encoding as BE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base58 as B58
import Data.Word (Word8)

-------------------------------------------------------------------------------
import Crypto.Multihash.Internal.Types
-------------------------------------------------------------------------------

-- | Convert a maybe type to an either type
maybeToEither :: l -> Maybe r -> Either l r
maybeToEither _ (Just res) = Right res
maybeToEither err _        = Left err

-- | Codes corresponding to the various hash algorithms
hashCodes :: [Word8]
hashCodes = map fromIntegral
                ([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x40, 0x41]::[Int])

-- | Convert a 'BS.ByteString' from a 'Base' into a 'BS.ByteString' in 'Base2'.
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

-- | Encode the binary data using a given 'Base'.
encoder :: ByteArrayAccess a => Base -> a -> Either String BA.Bytes
encoder base bs = case base of
            Base2  -> return $ BA.convert bs
            Base16 -> return $ BE.convertToBase BE.Base16 bs
            Base32 -> Left "Base32 encoder not implemented"
            Base58 -> return $ BA.convert $ B58.encodeBase58 B58.bitcoinAlphabet 
                                                             (BA.convert bs :: BS.ByteString)
            Base64 -> return $ BE.convertToBase BE.Base64 bs

-- | Compare the lenght of the encoded multihash digest with the encoded hash length.
--   Return 'True' if the lengths are matching.
badLength :: ByteArrayAccess bs => bs -> Bool
badLength mh = 
      case BA.length mh of
        n | n <= 2 -> True
        n | BA.index mh 1 /= (fromIntegral n-2) -> True
        _ -> False
