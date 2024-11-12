from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def pad_key(key, length=8):
    """
    Pad the key to ensure it is exactly `length` bytes.
    If the key is shorter, it will be padded with zeroes.
    If the key is longer, it will be truncated.

    Parameters:
    key (bytes): The input key to be padded.
    length (int): The required length for the key.

    Returns:
    bytes: The padded or truncated key of the required length.
    """
    if len(key) < length:
        key = key.ljust(length, b'\x00')  # pad with zeroes
    elif len(key) > length:
        key = key[:length]  # truncate to the required length
    return key

def des_encrypt(plain_text, key):
    """
    Encrypt the plain text using DES algorithm.
    
    Parameters:
    plain_text (str): The text to be encrypted.
    key (bytes): The encryption key (must be 8 bytes long).
    
    Returns:
    bytes: The encrypted cipher text.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plain_text.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text

def des_decrypt(cipher_text, key):
    """
    Decrypt the cipher text using DES algorithm.
    
    Parameters:
    cipher_text (bytes): The encrypted text to be decrypted.
    key (bytes): The decryption key (must be 8 bytes long).
    
    Returns:
    str: The decrypted plain text.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return decrypted_text.decode()

def main():
    """
    The main function to run the live application for DES encryption and decryption.
    """
    while True:
        print("\n=== DES Encryption and Decryption ===")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            print("\n--- Encrypting Text ---")
            
            # Generate a random 8-byte key for DES or allow user to input key
            key_choice = input("\nDo you want to provide your own key? (y/n): ").strip().lower()
            
            if key_choice == 'y':
                user_key = input("Enter a key (1-8 characters): ").encode()
                key = pad_key(user_key)  # pad the key to 8 bytes if necessary
                print(f"Using key: {key.hex()}")
            else:
                key = get_random_bytes(8)
                print(f"\nGenerated Key (in hexadecimal): {key.hex()}")

            # Input plaintext
            plain_text = input("Enter the plain text to encrypt: ")
            
            # Encrypt the plaintext
            encrypted_text = des_encrypt(plain_text, key)
            print(f"\nEncrypted Text (in hexadecimal): {encrypted_text.hex()}")

        elif choice == '2':
            print("\n--- Decrypting Text ---")
            
            # Input the key used for encryption
            key_input = input("Enter the key (in hexadecimal or 1-8 characters): ")
            
            try:
                if len(key_input) <= 16:  # User entered a key as text or hex string
                    if all(c in "0123456789abcdefABCDEF" for c in key_input):  # Hex format
                        key = binascii.unhexlify(key_input)
                    else:  # Text format, pad to 8 bytes if needed
                        key = pad_key(key_input.encode())
                else:
                    raise ValueError("Key must be at most 8 characters or 16 hex digits.")
                
                if len(key) != 8:
                    print("Error: Key must be exactly 8 bytes long after padding.")
                    continue
            except (binascii.Error, ValueError) as e:
                print(f"Error: {e}")
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
                decrypted_text = des_decrypt(cipher_text, key)
                print(f"\nDecrypted Text: {decrypted_text}")
            except ValueError:
                print("Error: Decryption failed. Incorrect key or ciphertext.")

        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
