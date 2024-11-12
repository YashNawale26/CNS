import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HexFormat;
import java.util.Scanner;

public class DigitalSignatureCLI {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private static final String RSA = "RSA";
    
    private static KeyPair keyPair;
    private static byte[] lastSignature;
    private static String lastMessage;

    public static byte[] createDigitalSignature(byte[] input, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(key);
        signature.update(input);
        return signature.sign();
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        System.out.println("---- Digital Signature CLI Application ----\n");

        while (!exit) {
            System.out.println("Choose an option:");
            System.out.println("1. Generate RSA Key Pair");
            System.out.println("2. Sign a Message");
            System.out.println("3. Verify a Signature");
            System.out.println("4. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // consume newline

            switch (choice) {
                case 1 -> {
                    System.out.println("\nGenerating RSA key pair (2048-bit)...");
                    keyPair = generateRSAKeyPair();
                    System.out.println("Key pair generated successfully!\n");
                }
                case 2 -> {
                    if (keyPair == null) {
                        System.out.println("Please generate a key pair first.\n");
                        continue;
                    }
                    System.out.print("Enter the message to sign: ");
                    lastMessage = scanner.nextLine();
                    lastSignature = createDigitalSignature(lastMessage.getBytes(), keyPair.getPrivate());
                    System.out.println("\nMessage signed successfully!");
                    System.out.println("Signature (Hex):\n" + HexFormat.of().formatHex(lastSignature) + "\n");
                }
                case 3 -> {
                    if (keyPair == null || lastSignature == null || lastMessage == null) {
                        System.out.println("Please generate a key pair and sign a message first.\n");
                        continue;
                    }
                    System.out.println("Verifying the last signed message...");
                    boolean isVerified = verifyDigitalSignature(lastMessage.getBytes(), lastSignature, keyPair.getPublic());
                    System.out.println("Verification Result: " + (isVerified ? "Signature is valid!" : "Signature is invalid!") + "\n");
                }
                case 4 -> {
                    exit = true;
                    System.out.println("Exiting the application. Goodbye!");
                }
                default -> System.out.println("Invalid choice. Please select a valid option.\n");
            }
        }

        scanner.close();
    }
}
