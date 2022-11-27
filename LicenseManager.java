import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class LicenseManager {
    public LicenseManager() {

    }

    public byte[] decryptRSA() {
        return null;
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
            hex = hex.substring(hex.length() - 2); // Get last two characters (for 2's complement bytes)
            sb.append(hex);

            if (i < input.length - 1) {
                sb.append(dlm);
            }
        }
        return sb.toString();
    }

    public String signHash() {
        return null;
    }
}
