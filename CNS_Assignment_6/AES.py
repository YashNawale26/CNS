from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def aes_encrypt(plain_text, key):
    """
    Encrypt the plain text using AES algorithm.
    
    Parameters:
    plain_text (str): The text to be encrypted.
    key (bytes): The encryption key (must be 16, 24, or 32 bytes long).
    
    Returns:
    tuple: Initialization vector (IV) and the encrypted cipher text.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return iv, encrypted_text

def aes_decrypt(iv, cipher_text, key):
    """
    Decrypt the cipher text using AES algorithm.
    
    Parameters:
    iv (bytes): The initialization vector used during encryption.
    cipher_text (bytes): The encrypted text to be decrypted.
    key (bytes): The decryption key (must be 16, 24, or 32 bytes long).
    
    Returns:
    str: The decrypted plain text.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_text.decode()

def main():
    """
    The main function to run the live application for AES encryption and decryption.
    """
    while True:
        print("\n=== AES Encryption and Decryption ===")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            print("\n--- Encrypting Text ---")
            
            # Generate or allow user to input AES key
            key_choice = input("\nDo you want to provide your own AES key? (y/n): ").strip().lower()
            if key_choice == 'y':
                user_key = input("Enter a key (up to 32 characters): ")
                if len(user_key) > 32:
                    print("Error: Key must be up to 32 characters long.")
                    continue
                key = user_key.encode().ljust(32, b'\0')  # Pad to 32 bytes
            else:
                key = get_random_bytes(32)  # Generate a 32-byte key (AES-256)
                print(f"\nGenerated Key (in hexadecimal): {key.hex()}")

            # Input plaintext
            plain_text = input("Enter the plain text to encrypt: ")
            
            # Encrypt the plaintext
            iv, encrypted_text = aes_encrypt(plain_text, key)
            print(f"\nInitialization Vector (IV) (in hexadecimal): {iv.hex()}")
            print(f"Encrypted Text (in hexadecimal): {encrypted_text.hex()}")

        elif choice == '2':
            print("\n--- Decrypting Text ---")
            
            # Input the AES key used for encryption
            key_input = input("Enter the AES key (in hexadecimal): ")
            try:
                key = binascii.unhexlify(key_input)
                if len(key) not in [16, 24, 32]:
                    print("Error: Key must be 16, 24, or 32 bytes long (32, 48, or 64 hex characters).")
                    continue
            except binascii.Error:
                print("Error: Invalid key format.")
                continue

            # Input the initialization vector (IV) in hexadecimal
            iv_input = input("Enter the IV (in hexadecimal): ")
            try:
                iv = binascii.unhexlify(iv_input)
            except binascii.Error:
                print("Error: Invalid IV format.")
                continue

            # Input the cipher text in hexadecimal
            cipher_text_input = input("Enter the encrypted text (in hexadecimal): ")
            try:
                cipher_text = binascii.unhexlify(cipher_text_input)
            except binascii.Error:
                print("Error: Invalid cipher text format.")
                continue

            # Decrypt the ciphertext
            try:
                decrypted_text = aes_decrypt(iv, cipher_text, key)
                print(f"\nDecrypted Text: {decrypted_text}")
            except ValueError:
                print("Error: Decryption failed. Incorrect key, IV, or ciphertext.")

        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
