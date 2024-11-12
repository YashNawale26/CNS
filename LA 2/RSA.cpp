#include <bits/stdc++.h>
using namespace std;

set<int> prime;  // a set of prime numbers
int public_key;  // stores the public key (e)
int private_key; // stores the private key (d)
int n;           // n = p * q (part of the key pair)

// Function to check if a number is prime
bool is_prime(int num) {
    if (num <= 1) return false;
    for (int i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) return false;
    }
    return true;
}

// Fill the prime set with primes up to 250
void primefiller() {
    cout << "Generating prime numbers up to 250...\n";
    for (int i = 2; i < 250; i++) {
        if (is_prime(i)) {
            prime.insert(i);
        }
    }
    cout << "Prime numbers generated and stored.\n";
}

void setkeys(int prime1, int prime2) {
    cout << "Setting up keys...\n";
    cout << "Selected primes p = " << prime1 << " and q = " << prime2 << endl;

    n = prime1 * prime2;
    cout << "Calculated n (p * q) = " << n << endl;

    int fi = (prime1 - 1) * (prime2 - 1);
    cout << "Calculated φ(n) = " << fi << endl;

    int e = 2;
    while (1) {
        if (__gcd(e, fi) == 1) break;
        e++;
    }
    public_key = e;
    cout << "Public key (e) selected as: " << public_key << endl;

    int d = 2;
    while (1) {
        if ((d * e) % fi == 1) break;
        d++;
    }
    private_key = d;
    cout << "Private key (d) calculated as: " << private_key << endl;
}

long long int encrypt(double message) {
    int e = public_key;
    long long int encrypted_text = 1;
    while (e--) {
        encrypted_text *= message;
        encrypted_text %= n;
    }
    return encrypted_text;
}

long long int decrypt(int encrypted_text) {
    int d = private_key;
    long long int decrypted = 1;
    while (d--) {
        decrypted *= encrypted_text;
        decrypted %= n;
    }
    return decrypted;
}

vector<int> encoder(string message) {
    vector<int> form;
    for (auto& letter : message) {
        form.push_back(encrypt((int)letter));
    }
    return form;
}

string decoder(vector<int> encoded) {
    string s;
    for (auto& num : encoded) {
        s += decrypt(num);
    }
    return s;
}

int main() {
    primefiller();

    // Input two distinct prime numbers from the user
    int prime1, prime2;
    cout << "Enter the first prime number (p): ";
    cin >> prime1;
    while (!is_prime(prime1)) {
        cout << "Invalid input. Please enter a prime number: ";
        cin >> prime1;
    }

    cout << "Enter the second prime number (q): ";
    cin >> prime2;
    while (!is_prime(prime2) || prime1 == prime2) {
        if (!is_prime(prime2)) {
            cout << "Invalid input. Please enter a prime number: ";
        } else {
            cout << "Both prime numbers must be distinct. Please enter another prime number: ";
        }
        cin >> prime2;
    }

    setkeys(prime1, prime2);

    string message;
    cout << "Input the text you want to encrypt: ";
    cin.ignore(); // Clear the newline character from the buffer
    getline(cin, message);

    vector<int> coded = encoder(message);
    cout << "\nInitial message:\n" << message << endl;

    cout << "\nThe encoded message (encrypted by public key):\n";
    for (auto& p : coded) cout << p << " ";
    cout << endl;

    cout << "\nThe decoded message (decrypted by private key):\n";
    cout << decoder(coded) << endl;

    return 0;
}
