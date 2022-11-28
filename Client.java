import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/*

    Run the program as "java Client.java from console if you are using Linux

*/

/**

    Signature Implementation Steps
-------------------------------------------------------------------------
    (Client)
    1- Get user info as string
    2- Encrypt the string with public key

    (Manager)
    3- Receive the encrypted package and decrypt it
    4- Create hash of the plaintext
    5- Sign the hash with private key (Use Signature class)

    (Client)
    6- Receive the signed package
    7- Verify the signature by hashing the plaintext again on client side
    (You should use public key for verification. That's the tricky part)

    8- Show a message prompt for result of the signing process
    9- Create a "license.txt" file
*/

public class Client {
    public Client() {

    }

    public static void main(String[] args) {
        Client client = new Client();
        LicenseManager manager = new LicenseManager();

        // retrieve network interface's MAC address
//        String mac = client.getMAC();
//        System.out.println("mac = " + mac);

         // Retrieve disk serial number
//        String DSN = client.getDiskSN();
//        System.out.println("DSN = " + DSN);

        // Retrieve motherboard's serial number
//        String MBSN = client.getMotherboardSN();
//        System.out.println("MBSN = " + MBSN);

    }

    public void runApplication() {
        System.out.println("Client started...");

        System.out.println("My MAC: " + getMAC());
        System.out.println("My Disk ID: " + getDiskSN());
        System.out.println("My Motherboard ID: " + getMotherboardSN());

        LicenseManager licenseManager = new LicenseManager();

        System.out.println("Client -- " + (isLicenseExistent() ? "License file found" : "License file is not found"));
        String info = getAllInfo();
        System.out.println("Client -- " + "Raw License Text: " + info);

        byte[] encrypted = encryptRSA(info.getBytes());
        System.out.println("Client -- " + "Encrypted License Text: " + new String(encrypted));

        String hashed = MD5(info);
        System.out.println("Client -- " + "MD5 License Text: " + hashed);

    }

    public String getMAC() {
        String macHex = "";
        try {
            InetAddress ip = Inet4Address.getLocalHost(); // Get device ip
            NetworkInterface device = NetworkInterface.getByInetAddress(ip); // Get network interface name

            byte[] mac = device.getHardwareAddress(); // Get mac address as a byte array

            macHex = bytesToHex(mac, ":");

        } catch (UnknownHostException | SocketException e) {
            e.printStackTrace();
            System.out.println("An error occurred on network configuration");
        }

        return macHex;
    }

    public String getDiskSN() { // TODO: Barış's part
        // Get the disk serial number of the device
        return null;
    }

    public String getMotherboardSN() { // Note: This function asks for sudo password
        String OS = System.getProperty("os.name").toLowerCase(); // OS name
        String sn = null; // Serial number to return

//        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        Console console = System.console();

        try {
            // Decide the command based on the operating system
            String cmd = ""; // Calling exec with a string parameter is deprecated
            if (OS.contains("linux")) { // Linux
                cmd = "sudo dmidecode -s baseboard-serial-number";
            } else if (OS.contains("win")) { // Windows
                cmd = "wmic baseboard get serialnumber";
            } else {
                System.out.println("The program is incompatible with your operating system");
            }

            System.out.println("cmd = " + cmd);

            if (console == null) {
                System.out.println("No console");
                return null;
            }

            // Execute the command
            Process serialNumberProcess = Runtime.getRuntime().exec(cmd);
            serialNumberProcess.waitFor();

            InputStreamReader ISR = new InputStreamReader(serialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);
            sn = br.readLine();

            serialNumberProcess.waitFor();
            br.close();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        return sn;
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

    // Returns all the info with "$" as separator
    public String getAllInfo() {
        return null;
    }

    public String getUsernameSerial() { // TODO: Barış's part
        // Return the username and the serial number (from the file or by use input)
        return null;
    }

    public boolean isLicenseExistent() { // TODO: Barış's part
        // Check if a file named "license.txt" does exist on current directory
        return false;
    }

    public byte[] encryptRSA(byte[] data) {
        byte[] encrypted = new byte[0];

        try {
            PublicKey publicKey = readPublicKey();

            // Encryption
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrypted = cipher.doFinal(data);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return encrypted;
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

    public PublicKey readPublicKey() {
        PublicKey publicKey = null;

        File publicFile = new File("public.key");

        try {
            // Key generation
            byte[] publicKeyBytes = Files.readAllBytes(publicFile.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = keyFactory.generatePublic(publicKeySpec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public boolean verifySignature(byte[] data, byte[] digitalSignature) {
        boolean isValid = false;

        try {
            Signature signature = Signature.getInstance("SHA256WithRSA");
            PublicKey publicKey = readPublicKey();
            signature.initVerify(publicKey);

            signature.update(data);
            isValid = signature.verify(digitalSignature);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }

        return isValid;
    }

    // TODO: Two functions below might be redundant
    public static byte[] readFile(String path) {
        byte[] buf = new byte[0];
        try {
            BufferedInputStream stream = new BufferedInputStream(new FileInputStream(path));

            int byteCount = stream.available();
            buf = new byte[byteCount];

            int i = stream.read(buf);

            for (byte d : buf) {
                System.out.println((char) d + ":" + d);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return buf;
    }

    public static void writeFile(byte[] data, String path) {
        try(OutputStream os = new FileOutputStream(path)){
            for (byte b : data) {
                os.write(b);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
