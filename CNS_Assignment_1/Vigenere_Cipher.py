def vigenere_encrypt(plain_text, key):
    """
    Encrypt the plain text using the Vigenere cipher.

    Parameters:
    plain_text (str): The input text to be encrypted.
    key (str): The key for the Vigenere cipher.

    Returns:
    str: The encrypted text.
    """
    plain_text = plain_text.upper().replace(" ", "")
    key = key.upper().replace(" ", "")
    key_length = len(key)
    encrypted_text = ""

    for i, char in enumerate(plain_text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text

def vigenere_decrypt(cipher_text, key):
    """
    Decrypt the cipher text using the Vigenere cipher.

    Parameters:
    cipher_text (str): The input text to be decrypted.
    key (str): The key for the Vigenere cipher.

    Returns:
    str: The decrypted text.
    """
    cipher_text = cipher_text.upper().replace(" ", "")
    key = key.upper().replace(" ", "")
    key_length = len(key)
    decrypted_text = ""

    for i, char in enumerate(cipher_text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += char

    return decrypted_text

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nVigenere Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text: ")
            key = input("Enter the key: ")
            encrypted_text = vigenere_encrypt(plain_text, key)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            encrypted_text = input("\nEnter the encrypted text: ")
            key = input("Enter the key: ")
            decrypted_text = vigenere_decrypt(encrypted_text, key)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

