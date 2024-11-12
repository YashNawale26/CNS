def euclidean_algorithm(a, b):
    """
    Compute the GCD of a and b using the Euclidean algorithm.
    
    Parameters:
    a (int): First integer.
    b (int): Second integer.
    
    Returns:
    int: The GCD of a and b.
    """
    while b != 0:
        a, b = b, a % b
    return a

def extended_euclidean_algorithm(a, b):
    """
    Compute the GCD of a and b, as well as the coefficients x and y 
    such that ax + by = gcd(a, b) using the Extended Euclidean algorithm.
    
    Parameters:
    a (int): First integer.
    b (int): Second integer.
    
    Returns:
    tuple: (gcd, x, y) where gcd is the GCD of a and b, and x, y are 
    the coefficients of Bézout's identity.
    """
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_euclidean_algorithm(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

def main():
    """
    The main function to run the program.
    """
    while True:
        print("\nEuclidean and Extended Euclidean Algorithm")
        print("1. Compute GCD using Euclidean Algorithm")
        print("2. Compute GCD and coefficients using Extended Euclidean Algorithm")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            a = int(input("\nEnter the first integer (a): "))
            b = int(input("Enter the second integer (b): "))
            gcd = euclidean_algorithm(a, b)
            print(f"\nGCD of {a} and {b} is: {gcd}")
        elif choice == '2':
            a = int(input("\nEnter the first integer (a): "))
            b = int(input("Enter the second integer (b): "))
            gcd, x, y = extended_euclidean_algorithm(a, b)
            print(f"\nGCD of {a} and {b} is: {gcd}")
            print(f"Coefficients x and y are: x = {x}, y = {y}")
            print(f"\nBézout's identity: {a}*({x}) + {b}*({y}) = {gcd}")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
