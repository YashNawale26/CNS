def caesar_encrypt(text, shift):
    """
    Encrypt the plain text using Caesar cipher.

    Parameters:
    text (str): The input text to be encrypted.
    shift (int): The number of positions to shift each character.

    Returns:
    str: The encrypted text.
    """
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                new_char = chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                new_char = chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            encrypted_text += new_char
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    """
    Decrypt the encrypted text using Caesar cipher.

    Parameters:
    text (str): The input text to be decrypted.
    shift (int): The number of positions to shift each character back.

    Returns:
    str: The decrypted text.
    """
    return caesar_encrypt(text, -shift)

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nCaesar Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text: ")
            shift = int(input("Enter the shift value: "))
            encrypted_text = caesar_encrypt(plain_text, shift)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            encrypted_text = input("Enter the encrypted text: ")
            shift = int(input("Enter the shift value: "))
            decrypted_text = caesar_decrypt(encrypted_text, shift)
            print(f"Decrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
