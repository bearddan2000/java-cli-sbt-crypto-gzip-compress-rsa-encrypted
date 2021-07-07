/*
 * copyright
 * http://timarcher.com/blog/2007/04/simple-java-class-to-des-encrypt-strings-such-as-passwords-and-credit-card-numbers/
 */

package example;

// Java program to perform the
// encryption and decryption
// using asymmetric key
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.xml.bind
    .DatatypeConverter;

public class Main {

    private static final String RSA
        = "RSA";
    private static Scanner sc;

    // Generating public & private keys
    // using RSA algorithm.
    public static KeyPair generateRSAKkeyPair()
        throws Exception
    {
        SecureRandom secureRandom
            = new SecureRandom();
        KeyPairGenerator keyPairGenerator
            = KeyPairGenerator.getInstance(RSA);

        keyPairGenerator.initialize(
            2048, secureRandom);
        return keyPairGenerator
            .generateKeyPair();
    }

    // Encryption function which converts
    // the plainText into a cipherText
    // using private Key.
    public static byte[] do_RSAEncryption(
        String plainText,
        PrivateKey privateKey)
        throws Exception
    {
        Cipher cipher
            = Cipher.getInstance(RSA);

        cipher.init(
            Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(
            plainText.getBytes());
    }

    // Decryption function which converts
    // the ciphertext back to the
    // original plaintext.
    public static String do_RSADecryption(
        byte[] cipherText,
        PublicKey publicKey)
        throws Exception
    {
        Cipher cipher
            = Cipher.getInstance(RSA);

        cipher.init(Cipher.DECRYPT_MODE,
                    publicKey);
        byte[] result
            = cipher.doFinal(cipherText);

        return new String(result);
    }

    // Driver code
    public static void main(String args[])
        throws Exception
    {

        KeyPair keypair
            = generateRSAKkeyPair();

        String plainText = "pass";

        byte[] cipherText
            = do_RSAEncryption(
                plainText,
                keypair.getPrivate());

        System.out.println(
            "The Public Key is: "
            + DatatypeConverter.printHexBinary(
                  keypair.getPublic().getEncoded()));

        System.out.println(
            "The Private Key is: "
            + DatatypeConverter.printHexBinary(
                  keypair.getPrivate().getEncoded()));

        System.out.print("The Encrypted Text is: ");

        String rsaText = DatatypeConverter.printHexBinary(cipherText);

        System.out.println(rsaText);

        System.out.println(String.format("The Encrypted Text length is: %d", rsaText.length()));

        byte[] compress = GZIPCompression.compress(rsaText);

        System.out.println(String.format("The Encrypted Compressed Text length is: %d", compress.length));

        rsaText = GZIPCompression.decompress(compress);

        System.out.println(String.format("The Encrypted Decompressed Text length is: %d", rsaText.length()));

        String decryptedText
            = do_RSADecryption(
                cipherText,
                keypair.getPublic());

        System.out.println(
            "The decrypted text is: "
            + decryptedText);
    }
}
