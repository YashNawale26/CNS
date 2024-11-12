def rail_fence_encrypt(plain_text, key):
    """
    Encrypt the plain text using the Rail Fence cipher.

    Parameters:
    plain_text (str): The input text to be encrypted.
    key (int): The number of rails (rows) for the Rail Fence cipher.

    Returns:
    str: The encrypted text.
    """
    # Create a list of strings to represent each rail
    rail = ['' for _ in range(key)]
    row, direction = 0, 1

    # Distribute the characters across the rails in a zigzag pattern
    for char in plain_text:
        rail[row] += char
        row += direction

        # Reverse direction when we reach the top or bottom rail
        if row == 0 or row == key - 1:
            direction *= -1

    # Concatenate all the rails to get the encrypted text
    return ''.join(rail)

def rail_fence_decrypt(cipher_text, key):
    """
    Decrypt the cipher text using the Rail Fence cipher.

    Parameters:
    cipher_text (str): The input text to be decrypted.
    key (int): The number of rails (rows) for the Rail Fence cipher.

    Returns:
    str: The decrypted text.
    """
    # Determine the length of each rail in the zigzag pattern
    pattern = [0] * len(cipher_text)
    row, direction = 0, 1

    for i in range(len(cipher_text)):
        pattern[i] = row
        row += direction

        # Reverse direction when we reach the top or bottom rail
        if row == 0 or row == key - 1:
            direction *= -1

    # Reconstruct the rails from the cipher text
    rail_lengths = [pattern.count(i) for i in range(key)]
    rail_chars = ['' for _ in range(key)]
    pos = 0

    for i in range(key):
        rail_chars[i] = cipher_text[pos:pos + rail_lengths[i]]
        pos += rail_lengths[i]

    # Reconstruct the original message by following the zigzag pattern
    result = []
    row_pointers = [0] * key
    for i in range(len(cipher_text)):
        result.append(rail_chars[pattern[i]][row_pointers[pattern[i]]])
        row_pointers[pattern[i]] += 1

    return ''.join(result)

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nRail Fence Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text: ").replace(" ", "")
            key = int(input("Enter the number of rails: "))
            encrypted_text = rail_fence_encrypt(plain_text, key)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            cipher_text = input("\nEnter the encrypted text: ").replace(" ", "")
            key = int(input("Enter the number of rails: "))
            decrypted_text = rail_fence_decrypt(cipher_text, key)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

