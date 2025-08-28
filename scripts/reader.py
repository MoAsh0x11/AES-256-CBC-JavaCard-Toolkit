from smartcard.System import readers
from smartcard.util import toHexString

CLA = 0x80
INS_SET_KEY = 0x10
INS_SET_IV = 0x11
INS_ENCRYPT = 0x20
INS_DECRYPT = 0x30

# Your Applet AID (hex)
APPLET_AID = [0xAE, 0x25, 0x6C, 0xBC, 0x00, 0x01]

def transmit(apdu, connection):
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"APDU: {toHexString(apdu)} -> SW1SW2: {sw1:02X}{sw2:02X}, Response: {toHexString(response)}")
    return response, sw1, sw2

def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]

# Connect to first reader
all_readers = readers()
if not all_readers:
    raise Exception("No smartcard readers found")

reader = all_readers[1]
print(f"Using reader: {reader}")
connection = reader.createConnection()
connection.connect()

# SELECT the applet using its AID
select_apdu = [0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)] + APPLET_AID
resp, sw1, sw2 = transmit(select_apdu, connection)
if (sw1, sw2) != (0x90, 0x00):
    raise Exception(f"Failed to select applet: SW1SW2 = {sw1:02X}{sw2:02X}")

# Prompt user for key and IV
key_hex = input("Enter 32-byte AES key (hex, 64 chars): ").strip()
key = bytes.fromhex(key_hex)
iv_hex = input("Enter 16-byte IV (hex, 32 chars): ").strip()
iv = bytes.fromhex(iv_hex)

# Send SET_KEY
apdu = [CLA, INS_SET_KEY, 0x00, 0x00, len(key)] + list(key)
transmit(apdu, connection)

# Send SET_IV
apdu = [CLA, INS_SET_IV, 0x00, 0x00, len(iv)] + list(iv)
transmit(apdu, connection)

# Prompt for action
action = input("Choose action (encrypt/decrypt): ").strip().lower()

if action == "encrypt":
    plaintext = input("Enter plaintext: ").encode()
    padded_plaintext = pkcs7_pad(plaintext)
    apdu = [CLA, INS_ENCRYPT, 0x00, 0x00, len(padded_plaintext)] + list(padded_plaintext)
    ciphertext, sw1, sw2 = transmit(apdu, connection)
    print(f"Ciphertext (hex): {toHexString(ciphertext)}")
elif action == "decrypt":
    ciphertext_hex = input("Enter ciphertext (hex): ").strip()
    ciphertext = bytes.fromhex(ciphertext_hex)
    if len(ciphertext) % 16 != 0:
        raise Exception("Ciphertext length must be multiple of 16 bytes")
    # Reset IV before decrypt
    apdu = [CLA, INS_SET_IV, 0x00, 0x00, len(iv)] + list(iv)
    transmit(apdu, connection)
    apdu = [CLA, INS_DECRYPT, 0x00, 0x00, len(ciphertext)] + list(ciphertext)
    plaintext, sw1, sw2 = transmit(apdu, connection)
    unpadded = pkcs7_unpad(bytes(plaintext))
    print(f"Plaintext: {unpadded.decode(errors='ignore')}")
else:
    print("Invalid action. Please choose 'encrypt' or 'decrypt'.")

