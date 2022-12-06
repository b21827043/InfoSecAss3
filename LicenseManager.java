import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

public class LicenseManager {
	
	byte[] decrypted;
	String hashed;
	byte[] signature;
	
    public LicenseManager() {
        System.out.println("LicenseManager service started...");
    }

    public void runManager(byte[] encrypted) {

        System.out.println("Server -- " + "Server is being requested...");

        System.out.println("Server -- " + "Incoming Encrypted Text: " + new String(encrypted));
        
        decrypted = decryptRSA(encrypted);
        String decryptedText = new String(decrypted);
        System.out.println("Server -- " + "Decrypted Text: " + decryptedText);
        
        hashed = MD5(decryptedText);
        System.out.println("Server -- " + "MD5 Plain License Text: " + hashed);
        
        signature = getSignature(hashed.getBytes());
        String signatureText = new String(signature);
        System.out.println("Server -- " + "Digital Signature: " + signatureText);
        
        
        
    }

    public byte[] encryptRSA(byte[] data) {
        byte[] encrypted = new byte[0];

        File publicFile = new File("public.key");

        try {
            // Key generation
            byte[] publicKeyBytes = Files.readAllBytes(publicFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            // Encryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrypted = cipher.doFinal(data);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException |
                 NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
        }

        return encrypted;
    }

    public byte[] decryptRSA(byte[] data) {
        byte[] decrypted = new byte[0];

        try {
            PrivateKey privateKey = readPrivateKey();

            // Decryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decrypted = cipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        }

        return decrypted;
    }

    public String MD5(String input) {
        String hash = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            hash = bytesToHex(digest, "");

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hash;
    }

    public String bytesToHex(byte[] input, String dlm) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length; i++) { // Parse bytes to hex string
            String hex = Integer.toHexString(input[i]);
            if (hex.length() < 2) {
            	hex = "0"+hex;
            }
            else {
                hex = hex.substring(hex.length() - 2); // Get last two characters (for 2's complement bytes)
            }

            sb.append(hex);

            if (i < input.length - 1) {
                sb.append(dlm);
            }
        }
        return sb.toString();
    }

    public byte[] getSignature(byte[] data) {
        byte[] digitalSignature = new byte[0];

        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            SecureRandom secureRandom = new SecureRandom();
            PrivateKey privateKey = readPrivateKey();

            signature.initSign(privateKey, secureRandom);
            signature.update(data);
            digitalSignature = signature.sign();

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return digitalSignature;
    }

    public PrivateKey readPrivateKey() {
        PrivateKey privateKey = null;

        File privateFile = new File("private.key");

        try {
            // Key generation
            byte[] privateKeyBytes = Files.readAllBytes(privateFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            privateKey = keyFactory.generatePrivate(privateKeySpec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
    

    
}


