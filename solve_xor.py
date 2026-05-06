
import binascii

def xor_bytes(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def solve():
    # Hex from output.txt
    hex_cipher = "134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9"
    cipher_bytes = binascii.unhexlify(hex_cipher)
    
    # Try common flag prefixes
    prefixes = [b"CTF{", b"HTB{", b"SKY-", b"flag"]
    
    for prefix in prefixes:
        # Derive potential 4-byte key
        key = bytes([cipher_bytes[i] ^ prefix[i] for i in range(4)])
        decrypted = xor_bytes(cipher_bytes, key)
        print(f"[*] Prefix '{prefix.decode()}' -> Key: {key.hex()} -> Result: {decrypted.decode('utf-8', errors='ignore')[:40]}")

if __name__ == "__main__":
    solve()
