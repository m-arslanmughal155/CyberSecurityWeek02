from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Encryption function
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization Vector
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_message).decode()

# Decryption function
def decrypt_message(encrypted_message, key):
    decoded_data = base64.b64decode(encrypted_message)
    iv = decoded_data[:AES.block_size]  # Extract the IV
    encrypted_message = decoded_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode()

# Key generation (AES-256 requires a 32-byte key)
def generate_key():
    return get_random_bytes(32)  # Generate a secure random 32-byte key

# Main demonstration
if __name__ == "__main__":
    # Generate a secure key
    key = generate_key()
    
    # Original message
    original_message = "This is a sample message for encryption."
    print(f"Original Message: {original_message}")

    # Encrypt the message
    encrypted_message = encrypt_message(original_message, key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, key)
    print(f"Decrypted Message: {decrypted_message}")
