import math

def create_matrix(text, key_len):
    """
    Create a matrix from the text with the specified number of columns (key length).
    """
    rows = math.ceil(len(text) / key_len)
    matrix = [['' for _ in range(key_len)] for _ in range(rows)]
    k = 0
    
    for i in range(rows):
        for j in range(key_len):
            if k < len(text):
                matrix[i][j] = text[k]
                k += 1
            else:
                matrix[i][j] = 'X'  # Padding with 'X' if the matrix is not full
    
    return matrix

def row_column_encrypt(plain_text, row_key, col_key):
    """
    Encrypt the plain text using row and column transformation.
    
    Parameters:
    plain_text (str): The input text to be encrypted.
    row_key (list): The key to rearrange rows.
    col_key (list): The key to rearrange columns.
    
    Returns:
    str: The encrypted text.
    """
    plain_text = plain_text.replace(" ", "")
    key_len = len(col_key)
    
    # Create the matrix from the plain text
    matrix = create_matrix(plain_text, key_len)
    
    # Apply the row key
    row_matrix = [matrix[i] for i in row_key]
    
    # Apply the column key
    encrypted_text = ""
    for row in row_matrix:
        encrypted_row = [row[j] for j in col_key]
        encrypted_text += ''.join(encrypted_row)
    
    return encrypted_text

def row_column_decrypt(cipher_text, row_key, col_key):
    """
    Decrypt the cipher text using row and column transformation.
    
    Parameters:
    cipher_text (str): The input text to be decrypted.
    row_key (list): The key to rearrange rows.
    col_key (list): The key to rearrange columns.
    
    Returns:
    str: The decrypted text.
    """
    key_len = len(col_key)
    rows = len(cipher_text) // key_len
    
    # Create the matrix to store the rearranged cipher text
    matrix = [['' for _ in range(key_len)] for _ in range(rows)]
    k = 0
    
    # Arrange the cipher text in the matrix based on the column key
    for i in range(len(row_key)):
        for j in col_key:
            matrix[row_key[i]][j] = cipher_text[k]
            k += 1
    
    # Read the decrypted text row by row
    decrypted_text = ""
    for i in range(rows):
        decrypted_text += ''.join(matrix[i])
    
    return decrypted_text

def main():
    """
    The main function to run the menu-driven program.
    """
    while True:
        print("\nRow and Column Transformation Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plain_text = input("\nEnter the plain text: ")
            row_key = list(map(int, input("Enter the row key as a sequence of numbers (e.g., 2 0 1): ").split()))
            col_key = list(map(int, input("Enter the column key as a sequence of numbers (e.g., 1 0 2): ").split()))
            encrypted_text = row_column_encrypt(plain_text, row_key, col_key)
            print(f"\nEncrypted Text: {encrypted_text}")
        elif choice == '2':
            cipher_text = input("\nEnter the encrypted text: ")
            row_key = list(map(int, input("Enter the row key as a sequence of numbers (e.g., 2 0 1): ").split()))
            col_key = list(map(int, input("Enter the column key as a sequence of numbers (e.g., 1 0 2): ").split()))
            decrypted_text = row_column_decrypt(cipher_text, row_key, col_key)
            print(f"\nDecrypted Text: {decrypted_text}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

