{-# LANGUAGE OverloadedStrings #-}

import Crypto.Multihash
import Data.ByteString (ByteString)
import Test.Hspec
import Text.Printf (printf)

main :: IO ()
main = hspec $ do
  testMHEncoding SHA1 ( "1114a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
                      , "5dt9CqvXK9qs7vazf7k7ZRqe28VPTg"
                      , "ERSpSo/lzLGbphxMCHPTkemHmC+70w==")
  testMHEncoding SHA256 ( "12209f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                        , "QmZ5NmGeStdit7tV6gdak1F8FyZhPsfA843YS9f2ywKH6w"
                        , "EiCfhtCBiEx9ZZov6qDFWtAVo79PGysLgizRXWwVsPAKCA==")
  testMHEncoding SHA512 ( "1340ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
                        , "8VxYhLL7s5BvLogtUGgNJ7DebZ5Ba9mG3izfc7v6o4RZ28x469vJaifa3TQ13Z9DycmAuJWnp7ErkZofm4rsMo78fQ"
                        , "E0DuJrDdSvfnSaoajuPBCumSP2GJgHcuRz+IGaXUlA4NsnrBhfig4dX4T4i8iH/WexQ3MsMEzF+prY5vV/UAKKj/")
  testMHEncoding SHA3_512 ( "14409ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"
                          , "8tXEcJyq2MCx27UHYbZxmte37ezBawV35QhfKPtq5QeSnX66q4DDf1cwMYUh2pUVbxdQgrDaSjbrPrfNxzvSSLQAtT"
                          , "FECezghum6xJH6xcHRBGyhHXN7kqKy69k/AF17cQEQwKZ4KIFm5/vnlog6Ty6bPKn0hPUh0M5GQ0XMGuyWd5FJwU")
  testMHEncoding SHA3_384 ( "1530e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd"
                          , "G9LerVN7c3uUAAymoAGkCGZPn53PZi1SHwPJ2nznLp82jcM2M1KLwpfrZh3F1QRVG3f2"
                          , "FTDlFtq7I7bjACaGNUMoJ4Cjrg3M8FVRzwKVF41/8PG0Huy52z/yGQB8TglyYNWGIb0=")
  testMHEncoding SHA3_256 ( "162036f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
                          , "W1d9SeHn1mCnY3jZMs5YeqfFbwEnq5gQy1VDymGoPK28RD"
                          , "FiA28ChYC7AsyCcqmgIPQgDjRuJ2rmZORe6AdFV04vWrgA==")
  testMHEncoding SHA3_224 ( "171c3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"
                          , "5daZNVMeTfSuCvu7rBKsFkzEMebnuGjNpos1ThF1c"
                          , "Fxw3l78K+7/KSnu7p2AqK1UnRodlF6f5t84tsK57")
  testMHEncoding Blake2b_512 ( "4040a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572"
                             , "S2XUqUDxz3MHMZtJpCZKt5oRjXHQ34gsyDBT759qNwoSP9rDBHVHxjQUQtXfExotxTqf4rMEXQkNmXE3N9mhoZX6wK"
                             , "QECnEHnUKFPeom5FMAQzhnClOBS3gTf/vtB2A6QddqSDqpvDO1gvd9MKZebymolsBBHzgxLh1m4L8WOGyGqJvqVy")
  testMHEncoding Blake2s_256 ( "4120f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e"
                             , "2UPuEK7FVakwP3yUak5jKQhZb6pgpbcqYoRZ2tDzgeCfVr5"
                             , "QSDzCPwCzpFyrQKn11gA7PwCcQm8Z5h+oyq6m43MexAVDg==")
  where
    testMHEncoding :: (HashAlgorithm a, Codable a, Show a) => a 
                      -> (String, String, String) -> SpecWith ()
    testMHEncoding alg (sm16, sm58, sm64) = do
        describe (printf "Encoding %s multihash" (show alg)) $ do
          it "returns the correct Base16 hash" $ 
            encode Base16 m `shouldBe` sm16
          it "returns the correct Base58 hash" $ 
            encode Base58 m `shouldBe` sm58
          it "returns the correct Base64 hash" $ 
            encode Base64 m `shouldBe` sm64
      where 
        m = multihash alg ("test"::ByteString)
  