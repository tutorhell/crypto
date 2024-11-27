import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class DESv2 {
    String secret, message;
    byte[] secretKey;

    public DESv2() throws Exception {
        Scanner sc = new Scanner(System.in);

        // Input secret and message
        System.out.println("Enter the secret:");
        secret = sc.next();
        secretKey = generateKey(secret);

        System.out.println("Enter the message:");
        message = sc.next();

        // Encrypt and Decrypt
        String encrypted = encrypt(secretKey, message);
        System.out.println("Encrypted text: " + encrypted);

        String decrypted = decrypt(secretKey, encrypted);
        System.out.println("Decrypted text: " + decrypted);

        sc.close();
    }

    // Generate a DESv2 key based on a secret
    public byte[] generateKey(String secret) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("DES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(secret.getBytes());
        kgen.init(56, sr); // DES uses a 56-bit key
        SecretKey skey = kgen.generateKey();
        return skey.getEncoded();
    }

    // Encrypt the message
    public String encrypt(byte[] secretKey, String message) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted); // Encode to Base64
    }

    // Decrypt the ciphertext
    public String decrypt(byte[] secretKey, String cipherText) throws Exception {
        SecretKey key = new SecretKeySpec(secretKey, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedCipherText = Base64.getDecoder().decode(cipherText); // Decode Base64
        byte[] decrypted = cipher.doFinal(decodedCipherText);
        return new String(decrypted);
    }

    // Main method
    public static void main(String[] args) throws Exception {
        new DESv2();
    }
}
