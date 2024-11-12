#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <cstring>

using namespace std;

#define BLOCK_SIZE 64  // 512-bit block size (64 bytes)

// Circular left shift (rotate left)
unsigned int leftRotate(unsigned int value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

// SHA-1 padding
string padMessage(const string& input) {
    unsigned long long originalLength = input.size() * 8; // in bits
    string paddedMessage = input;

    // Append a '1' bit followed by '0' bits until the length is congruent to 448 mod 512
    cout << "\n=== Padding the Message ===\n";
    cout << "Original message length (in bits): " << originalLength << endl;

    paddedMessage += static_cast<char>(0x80);  // 0x80 is binary: 10000000
    while (paddedMessage.size() % 64 != 56) {
        paddedMessage += static_cast<char>(0x00);
    }

    // Append the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        paddedMessage += static_cast<char>((originalLength >> (i * 8)) & 0xFF);
    }

    cout << "Padded message length (in bytes): " << paddedMessage.size() << endl;
    cout << "Message after padding (in hex): ";
    for (unsigned char c : paddedMessage) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << "\n\n";

    return paddedMessage;
}

// Process message in 512-bit chunks (64 bytes)
void processChunk(const string& chunk, unsigned int* H) {
    unsigned int W[80];

    // Break chunk into sixteen 32-bit big-endian words W[0..15]
    cout << "\nProcessing 512-bit chunk:\n";
    for (int i = 0; i < 16; ++i) {
        W[i] = (chunk[i * 4 + 0] & 0xFF) << 24 |
               (chunk[i * 4 + 1] & 0xFF) << 16 |
               (chunk[i * 4 + 2] & 0xFF) << 8 |
               (chunk[i * 4 + 3] & 0xFF);
        cout << "W[" << i << "]: " << hex << setw(8) << setfill('0') << W[i] << endl;
    }

    // Extend the sixteen 32-bit words into eighty 32-bit words
    for (int i = 16; i < 80; ++i) {
        W[i] = leftRotate(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }

    // Initialize hash value for this chunk
    unsigned int a = H[0];
    unsigned int b = H[1];
    unsigned int c = H[2];
    unsigned int d = H[3];
    unsigned int e = H[4];

    // Main loop
    for (int i = 0; i < 80; ++i) {
        unsigned int f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        unsigned int temp = leftRotate(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = leftRotate(b, 30);
        b = a;
        a = temp;
    }

    // Add this chunk's hash to result so far
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;

    cout << "\nUpdated hash values after processing chunk:\n";
    for (int i = 0; i < 5; ++i) {
        cout << "H[" << i << "]: " << hex << setw(8) << setfill('0') << H[i] << endl;
    }
}

// Convert hash values to hexadecimal string
string hashToHexString(const unsigned int* H) {
    stringstream ss;
    for (int i = 0; i < 5; ++i) {
        ss << hex << setw(8) << setfill('0') << H[i];
    }
    return ss.str();
}

// Main SHA-1 function
string sha1(const string& input) {
    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 5 primes)
    unsigned int H[5] = {
        0x67452301,  // H0
        0xEFCDAB89,  // H1
        0x98BADCFE,  // H2
        0x10325476,  // H3
        0xC3D2E1F0   // H4
    };

    // Step 1: Pad the message
    string paddedMessage = padMessage(input);

    // Step 2: Process the message in 512-bit chunks
    for (size_t i = 0; i < paddedMessage.size(); i += 64) {
        processChunk(paddedMessage.substr(i, 64), H);
    }

    // Step 3: Produce the final hash value (big-endian)
    return hashToHexString(H);
}

int main() {
    string message;
    cout << "=== SHA-1 Hashing CLI ===\n";
    cout << "Enter the Message: ";
    getline(cin, message);

    cout << "\n=== Computing SHA-1 Hash ===\n";
    string sha1Hash = sha1(message);
    cout << "\n=== Final SHA-1 Hash ===\n";
    cout << "SHA-1 Hash: " << sha1Hash << endl;

    return 0;
}
