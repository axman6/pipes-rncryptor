module Crypto.RNCryptor.V3.Pipes.Encode where

import           Pipes
import           Pipes.Prelude as P
import           Data.ByteString as BS
import           Crypto.RNCryptor.V3.Encrypt as E
import           Crypto.RNCryptor.Types as E
import           Crypto.RNCryptor.Padding as E
import           Data.Monoid

-- import           Control.Monad.IO.Class (liftIO)

encrypt :: MonadIO m => ByteString -> Pipe ByteString ByteString m ()
encrypt userKey = do
    (hdrbs,ctx) <- liftIO $ do
        hdr <- newRNCryptorHeader userKey
        return (renderRNCryptorHeader hdr,newRNCryptorContext userKey hdr)
    yield hdrbs
    P.scan (\ct bs -> encryptBlock (fst ct) bs) (ctx,BS.empty) snd

    where
        finaliseEncryption lastBlock ctx = do
          let inSz = BS.length lastBlock
              padding = pkcs7Padding blockSize inSz
          yield (snd $ encryptBlock ctx (lastBlock <> padding))
          -- Finalise the block with the HMAC
          yield ((rncHMAC . ctxHeader $ ctx) mempty)
