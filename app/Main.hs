{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Multihash
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.List
import System.Console.GetOpt
import System.IO hiding (withFile)
import System.Environment
import System.Exit
import Text.Printf (printf)

main :: IO ()
main = do
  (_args, files) <- getArgs >>= parse
  mapM_ printers files
  putStrLn "Done! Note: shake-128/256 are not yet part of the library"
 
printer :: (HashAlgorithm a, Codable a, Show a) => a -> ByteString -> IO ()
printer alg bs = do
  let m = multihash alg bs
  putStrLn $ printf "Hash algorithm: %s" (show alg)
  putStrLn $ printf "Base16: %s" (encode' Base16 m :: String)
  putStrLn $ printf "Base32: %s" (encode' Base32 m :: String)
  putStrLn $ printf "Base58: %s" (encode' Base58 m :: String)
  putStrLn $ printf "Base64: %s" (encode' Base64 m :: String)
  putStrLn ""

printers :: FilePath -> IO ()
printers f = do
  d <- withFile f
  putStrLn $ printf "Hashing %s\n" (if f == "-" then show d else show f)
  printer SHA1 d
  printer SHA256 d
  printer SHA512 d
  printer SHA3_512 d
  printer SHA3_384 d
  printer SHA3_256 d
  printer SHA3_224 d
  printer Blake2b_512 d
  printer Blake2s_256 d
  putStrLn ""
  where withFile f = if f == "-" then B.getContents else B.readFile f

data Flag = Help                  -- --help
          deriving (Eq,Ord,Enum,Show,Bounded)
 
flags :: [OptDescr Flag]
flags = [Option [] ["help"] (NoArg Help) "Print this help message"]

parse :: [String] -> IO ([Flag], [String])
parse argv = case getOpt Permute flags argv of
    (args,fs,[]) -> do
        let files = if null fs then ["-"] else fs
        if Help `elem` args
            then do hPutStrLn stderr (usageInfo header flags)
                    exitSuccess
            else return (nub (concatMap set args), files)
 
    (_,_,errs)   -> do
        hPutStrLn stderr (concat errs ++ usageInfo header flags)
        exitWith (ExitFailure 1)
 
    where header = "Usage: mh [file ...]"
          set f  = [f]
