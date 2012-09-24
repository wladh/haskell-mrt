{-# LANGUAGE BangPatterns #-}

{- A parser for MRT files as described by RFC6396 -}

module MRTFile
    ( RTInfo (..)
    , parseMRTFileToIPv4RTable
    ) where

import Data.Word
import Data.IP
import Data.IP.RouteTable (IPRTable)
import qualified Data.IP.RouteTable as RT
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Binary.Get
import Control.Applicative
import Data.Bits
import System.Posix.Types
import System.Locale
import Data.Time.Format
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.Int
import Data.List

data Message = PeerTable { cBGPId :: !IPv4
                         , vName  :: !ByteString
                         , peers  :: ![PeerEntry]
                         }
             | RIB { ribType :: !RIBEntryType
                   , seqNo   :: !Word32
                   , prefix  :: !IPRange
                   , rib     :: ![RIBEntry]
                   }
             | MessageTypeNotSupported
               deriving (Eq, Show)

data RIBEntryType = RIBIPv4Unicast
                  | RIBIPv4Multicast
                  | RIBIPv6Unicast
                  | RIBIPv6Multicast
                    deriving (Eq, Show)

data ASN = ASN16 !Word16
         | ASN32 !Word32
           deriving (Eq)

instance Show ASN where
    show (ASN16 a) = show a
    show (ASN32 a) = show a

data ASPathSegment = ASSet ![ASN]
                   | ASSequence ![ASN]
                     deriving (Eq)

instance Show ASPathSegment where
    show (ASSet p) = " { " ++ showASList p ++ " } "
    show (ASSequence p) = showASList p

showASList :: [ASN] -> String
showASList l = unwords $ map show l

data PeerEntry = PeerEntry { pBGPId :: !IPv4
                           , peerIP :: !IP
                           , peerAS :: !ASN
                           } deriving (Eq, Show)

data RIBEntry = RIBEntry { peerIdx :: !Int32
                         , oTime   :: !EpochTime
                         , attrs   :: ![BGPAttr]
                         } deriving (Eq, Show)

data BGPAttr = ASPath ![ASPathSegment]
             | BGPAttrUnsupported
               deriving (Eq, Show)

data RTInfo = RTInfo { originTime :: !UTCTime
                     , asPath     :: ![ASPathSegment]
                     } deriving (Eq)

instance Show RTInfo where
    show (RTInfo t a) = show a ++ " " ++ formatTime defaultTimeLocale "%c" t

isASPath :: BGPAttr -> Bool
isASPath (ASPath _) = True
isASPath _ = False

fromASPath :: BGPAttr -> [ASPathSegment]
fromASPath (ASPath x) = x

getIPv4 :: Get IPv4
getIPv4 =  (toIPv4 . map fromIntegral . B.unpack) <$> getByteString 4

getIPv6 :: Get IPv6
getIPv6 =  (toIPv6 . w16 [] . map fromIntegral . B.unpack) <$> getByteString 16
    where w16 xs [] = xs
          w16 xs (y:y':ys) = w16 (xs ++ [y * 16 + y']) ys

getPrefix :: Int -> Int -> Get [Int]
getPrefix tl pl = do
  bs <- getByteString bl
  return $ map fromIntegral $ B.unpack bs ++ replicate (tl - bl) 0
    where bl = (pl + 7) `div` 8

getIPv4Prefix :: Int -> Get IPRange
getIPv4Prefix l = (IPv4Range . flip makeAddrRange l . toIPv4) <$> getPrefix 4 l

getIPv6Prefix :: Int -> Get IPRange
getIPv6Prefix l = (IPv6Range . flip makeAddrRange l . toIPv6) <$> getPrefix 16 l

parseASPath :: Int -> Get BGPAttr
parseASPath len = ASPath <$> parseASPathSegments len
      where parseASPathSegments l | l < 0 = fail "BGP AS path parse"
                                  | l == 0 = return []
                                  | otherwise = do
              ptype <- getWord8
              plen <- fromIntegral <$> getWord8
              path <- mapM (\s -> ASN32 <$> getWord32be) [1 .. plen]
              seg <- case ptype of
                       1 -> return $ ASSet path
                       2 -> return $ ASSequence path
                       x -> fail $ "Invalid path type " ++ show x
              xs <- parseASPathSegments (l - 4 * plen - 2)
              return $ seg : xs

parseBGPAttrs :: Int -> Get [BGPAttr]
parseBGPAttrs len | len < 0   = fail "BGP attributes parse"
                  | len == 0  = return []
                  | otherwise = do
  flags <- getWord8
  code <- getWord8
  alen <- if extendedLength flags
          then fromIntegral <$> getWord16be
          else fromIntegral <$> getWord8
  attr <- case code of
            2 -> parseASPath alen
            _ -> skip alen >> return BGPAttrUnsupported
  xs <- parseBGPAttrs (len - headerLen flags - alen)
  case attr of
    BGPAttrUnsupported -> return xs
    a -> return $ a : xs
 where extendedLength f = f .&. 16 == 16
       headerLen f = 3 + if extendedLength f then 1 else 0

parseRIBEntry :: Get RIBEntry
parseRIBEntry = do
  idx <- getWord16be
  ot <- getWord32be
  alen <- getWord16be
  attrs <- parseBGPAttrs (fromIntegral alen)
  return $ RIBEntry (fromIntegral idx) (fromIntegral ot) attrs

parseRIB :: RIBEntryType -> Get Message
parseRIB t = do
  s <- getWord32be
  plen <- fromIntegral <$> getWord8
  range <- case t of
             RIBIPv4Unicast   -> getIPv4Prefix plen
             RIBIPv4Multicast -> getIPv4Prefix plen
             RIBIPv6Unicast   -> getIPv6Prefix plen
             RIBIPv6Multicast -> getIPv6Prefix plen
  rcnt <- getWord16be
  entries <- mapM (const parseRIBEntry) [1 .. fromIntegral rcnt]
  return $ RIB t s range entries

parsePeerEntry :: Get PeerEntry
parsePeerEntry = do
  ptype <- getWord8
  bgpid <- getIPv4
  pip <- if even ptype then IPv4 <$> getIPv4 else IPv6 <$> getIPv6
  pas <- if even (ptype `div` 2)
         then ASN16 <$> getWord16be
         else ASN32 <$> getWord32be
  return $ PeerEntry bgpid pip pas

parsePeerTable :: Get Message
parsePeerTable = do
  bgpid <- getIPv4
  vlen <- getWord16be
  name <- getByteString (fromIntegral vlen)
  pcnt <- getWord16be
  entries <- mapM (const parsePeerEntry) [1 .. fromIntegral pcnt]
  return $ PeerTable bgpid name entries

parseMessage :: Get Message
parseMessage = do
  skip 4
  mType <- getWord16be
  mSubType <- getWord16be
  len <- getWord32be
  case (mType, mSubType) of
    (13, 1) -> parsePeerTable
    (13, 2) -> parseRIB RIBIPv4Unicast
    (13, 3) -> parseRIB RIBIPv4Multicast
    (13, 4) -> parseRIB RIBIPv6Unicast
    (13, 5) -> parseRIB RIBIPv6Multicast
    _ -> skip (fromIntegral len) >> return MessageTypeNotSupported

parseMRTFileToIPv4RTable :: FilePath -> IO (IPRTable IPv4 RTInfo)
parseMRTFileToIPv4RTable f = parse RT.empty parseMessage <$> BL.readFile f
    where parse rt _ c | c == BL.empty = rt
          parse rt p c = let (!m, !c', _) = runGetState p c 0
                             !rt' = addRoute rt m
                         in parse rt' p c'
          addRoute rt (RIB RIBIPv4Unicast _ (IPv4Range p) (h:hs)) =
              let time = posixSecondsToUTCTime (realToFrac $ oTime h)
                  a = filter isASPath $ attrs h
                  path = if a == [] then [] else fromASPath . head $ a
              in RT.insert p (RTInfo time path) rt
          addRoute rt _ = rt
