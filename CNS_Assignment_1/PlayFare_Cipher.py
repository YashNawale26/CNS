def generate_playfair_matrix(key):
    """
    Generate a 5x5 matrix for the Playfair cipher based on the provided key.

    Parameters:
    key (str): The key to generate the matrix.

    Returns:
    list: A 5x5 matrix for the Playfair cipher.
    """
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for char in key:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)

    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used:
            used.add(char)
            matrix.append(char)

    # Create a 5x5 matrix from the list
    matrix_5x5 = [matrix[i:i + 5] for i in range(0, 25, 5)]

    # Print the key matrix in square form
    print("\nGenerated Playfair Matrix:")
    for row in matrix_5x5:
        print(" ".join(row))

    return matrix_5x5


def find_position(matrix, char):
    """
    Find the row and column of a character in the Playfair matrix.

    Parameters:
    matrix (list): The 5x5 matrix for the Playfair cipher.
    char (str): The character to find in the matrix.

    Returns:
    tuple: The row and column of the character in the matrix.
    """
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(text, key):
    """
    Encrypt the plain text using the Playfair cipher.

    Parameters:
    text (str): The input text to be encrypted.
    key (str): The key for the Playfair cipher.

    Returns:
    str: The encrypted text.
    """
    text = text.upper().replace("J", "I").replace(" ", "")
    if len(text) % 2 != 0:
        text += "X"

    matrix = generate_playfair_matrix(key)
    encrypted_text = ""

    for i in range(0, len(text), 2):
        char1, char2 = text[i], text[i + 1]

        if char1 == char2:
            char2 = 'X'

        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)

        if row1 == row2:
            encrypted_text += matrix[row1][(col1 + 1) % 5]
            encrypted_text += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            encrypted_text += matrix[(row1 + 1) % 5][col1]
            encrypted_text += matrix[(row2 + 1) % 5][col2]
        else:
            encrypted_text += matrix[row1][col2]
            encrypted_text += matrix[row2][col1]

    return encrypted_text

def playfair_decrypt(text, key):
    """
    Decrypt the encrypted text using the Playfair cipher.

    Parameters:
    text (str): The input text to be decrypted.
    key (str): The key for the Playfair cipher.

    Returns:
    str: The decrypted text.
    """
    text = text.upper().replace("J", "I").replace(" ", "")
    matrix = generate_playfair_matrix(key)
    decrypted_text = ""

    for i in range(0, len(text), 2):
        char1, char2 = text[i], text[i + 1]

        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)

        if row1 == row2:
            decrypted_text += matrix[row1][(col1 - 1) % 5]
            decrypted_text += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            decrypted_text += matrix[(row1 - 1) % 5][col1]
            decrypted_text += matrix[(row2 - 1) % 5][col2]
        else:
            decrypted_text += matrix[row1][col2]
            decrypted_text += matrix[row2][col1]

    return decrypted_text

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nPlayfair Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text: ")
            key = input("Enter the key: ")
            encrypted_text = playfair_encrypt(plain_text, key)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            encrypted_text = input("\nEnter the encrypted text: ")
            key = input("Enter the key: ")
            decrypted_text = playfair_decrypt(encrypted_text, key)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

