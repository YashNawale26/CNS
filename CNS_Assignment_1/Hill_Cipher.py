import numpy as np

def mod_inverse(matrix, modulus):
    """
    Calculate the modular inverse of a matrix under a given modulus.

    Parameters:
    matrix (numpy.ndarray): The matrix to invert.
    modulus (int): The modulus value.

    Returns:
    numpy.ndarray: The modular inverse of the matrix.
    """
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_modulus_inv = (
        det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    )
    return matrix_modulus_inv

def hill_encrypt(text, key):
    """
    Encrypt the plain text using the Hill cipher.

    Parameters:
    text (str): The input text to be encrypted.
    key (list of int): The key for the Hill cipher as a flat list.

    Returns:
    str: The encrypted text.
    """
    size = int(len(key) ** 0.5)
    key_matrix = np.array(key).reshape(size, size)
    modulus = 26
    text_vector = np.array([ord(char) - ord('A') for char in text])
    text_vector = text_vector.reshape(-1, size).T
    encrypted_vector = (np.dot(key_matrix, text_vector) % modulus).T
    encrypted_text = ''.join(chr(num + ord('A')) for num in encrypted_vector.flatten())
    return encrypted_text

def hill_decrypt(text, key):
    """
    Decrypt the encrypted text using the Hill cipher.

    Parameters:
    text (str): The input text to be decrypted.
    key (list of int): The key for the Hill cipher as a flat list.

    Returns:
    str: The decrypted text.
    """
    size = int(len(key) ** 0.5)
    key_matrix = np.array(key).reshape(size, size)
    modulus = 26
    key_matrix_inv = mod_inverse(key_matrix, modulus)
    text_vector = np.array([ord(char) - ord('A') for char in text])
    text_vector = text_vector.reshape(-1, size).T
    decrypted_vector = (np.dot(key_matrix_inv, text_vector) % modulus).T
    decrypted_text = ''.join(chr(int(num) + ord('A')) for num in decrypted_vector.flatten())
    return decrypted_text

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nHill Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text (length multiple of key matrix size): ").upper().replace(" ", "")
            key = input("Enter the key matrix (comma-separated integers, e.g., '2,4,5,9' for 2x2 matrix): ")
            key_matrix = list(map(int, key.split(',')))
            size = int(len(key_matrix) ** 0.5)
            if len(plain_text) % size != 0:
                print("Error: The length of the plain text must be a multiple of the key matrix size.")
                continue
            encrypted_text = hill_encrypt(plain_text, key_matrix)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            encrypted_text = input("\nEnter the encrypted text: ").upper().replace(" ", "")
            key = input("Enter the key matrix (comma-separated integers, e.g., '2,4,5,9' for 2x2 matrix): ")
            key_matrix = list(map(int, key.split(',')))
            size = int(len(key_matrix) ** 0.5)
            if len(encrypted_text) % size != 0:
                print("Error: The length of the encrypted text must be a multiple of the key matrix size.")
                continue
            decrypted_text = hill_decrypt(encrypted_text, key_matrix)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
