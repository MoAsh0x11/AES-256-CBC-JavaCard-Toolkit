/*
 * Aes256Applet.java
 * Minimal Java Card applet that performs AES-256 CBC encryption/decryption.
 *
 * APDU protocol (CLA = 0x80 by default):
 *   INS 0x10: SET_KEY
 *       Data: 32-byte AES key
 *       Resp: none
 *   INS 0x11: SET_IV
 *       Data: 16-byte IV
 *       Resp: none
 *   INS 0x20: ENCRYPT (CBC/NoPad)
 *       Data: plaintext (len % 16 == 0)
 *       Resp: ciphertext (same length)
 *   INS 0x30: DECRYPT (CBC/NoPad)
 *       Data: ciphertext (len % 16 == 0)
 *       Resp: plaintext (same length)
 *
 * Notes:
 * - Not all cards support 256-bit AES keys. If not supported,
 *   installation will throw CryptoException.NO_SUCH_ALGORITHM or ILLEGAL_VALUE.
 * - This applet uses CBC with NoPadding; handle padding at the host side if needed.
 * - IV must be re-sent (SET_IV) before each new message to ensure semantic security.
 */

package com.sec.aes;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class aes_applet extends Applet {

    // ===== APDU protocol =====
    private static final byte CLA_LOCAL      = (byte) 0x80;
    private static final byte INS_SET_KEY    = (byte) 0x10;
    private static final byte INS_SET_IV     = (byte) 0x11;
    private static final byte INS_ENCRYPT    = (byte) 0x20;
    private static final byte INS_DECRYPT    = (byte) 0x30;

    private static final short AES_BLOCK_LEN = (short) 16;
    private static final short AES_256_LEN   = (short) 32; // 256 bits

    // ===== Crypto state =====
    private AESKey aesKey;
    private Cipher aesCbc;
    private byte[] iv;

    // Optional transient work buffer (avoids allocating on each call)
    private byte[] workBuf;

    protected aes_applet() {
        // Build AES-256 key object (persistent)
        try {
            aesKey = (AESKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_AES,
                    KeyBuilder.LENGTH_AES_256,
                    false // persistent
            );
        } catch (CryptoException e) {
            // Some cards throw ILLEGAL_VALUE if 256-bit is not supported
            ISOException.throwIt((short) (ISO7816.SW_FUNC_NOT_SUPPORTED & 0xFFFF));
        }

        // AES-CBC/NoPadding cipher instance
        try {
            aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (ISO7816.SW_FUNC_NOT_SUPPORTED & 0xFFFF));
        }

        // Allocate IV + work buffer
        iv = new byte[AES_BLOCK_LEN];
        workBuf = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new aes_applet();
    }

    public boolean select() {
        // Clear IV on select for safety; host must set before use
        Util.arrayFillNonAtomic(iv, (short) 0, AES_BLOCK_LEN, (byte) 0x00);
        return true;
    }

    public void deselect() { /* nothing */ }

    public void process(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] != CLA_LOCAL) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_SET_KEY:
                setKey(apdu);
                break;
            case INS_SET_IV:
                setIv(apdu);
                break;
            case INS_ENCRYPT:
                encrypt(apdu);
                break;
            case INS_DECRYPT:
                decrypt(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void setKey(APDU apdu) {
        short lc = readIncoming(apdu);
        if (lc != AES_256_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] buf = apdu.getBuffer();
        aesKey.setKey(buf, ISO7816.OFFSET_CDATA);
        // No response data
    }

    private void setIv(APDU apdu) {
        short lc = readIncoming(apdu);
        if (lc != AES_BLOCK_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, iv, (short) 0, AES_BLOCK_LEN);
    }

    private void encrypt(APDU apdu) {
        short lc = readIncoming(apdu);
        requireBlockMultiple(lc);

        byte[] buf = apdu.getBuffer();
        // Initialize cipher fresh with IV for each message
        aesCbc.init(aesKey, Cipher.MODE_ENCRYPT, iv, (short) 0, AES_BLOCK_LEN);
        short outLen = aesCbc.doFinal(buf, ISO7816.OFFSET_CDATA, lc, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private void decrypt(APDU apdu) {
        short lc = readIncoming(apdu);
        requireBlockMultiple(lc);

        byte[] buf = apdu.getBuffer();
        aesCbc.init(aesKey, Cipher.MODE_DECRYPT, iv, (short) 0, AES_BLOCK_LEN);
        short outLen = aesCbc.doFinal(buf, ISO7816.OFFSET_CDATA, lc, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    // ===== Helpers =====
    private static void requireBlockMultiple(short len) throws ISOException {
        if ((short) (len % AES_BLOCK_LEN) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /**
     * Receives full incoming data into APDU buffer and returns LC.
     */
    private static short readIncoming(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short) (apdu.setIncomingAndReceive());
        short bytesRead = lc;
        while (bytesRead < (short) (buf[ISO7816.OFFSET_LC] & 0xFF)) {
        	bytesRead += apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + bytesRead));        }
        return (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
    }
}
