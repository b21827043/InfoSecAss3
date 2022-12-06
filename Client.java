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
	
	static String username = "abt";
	static String userSerialNumber = "1234-5678-9012";
	static String mac = "F0:2F:74:15:F1:CD";
	static String DSN = "-455469999";
	static String MBSN = "201075710502043";
	
	
    public Client() {
    	System.out.println("Client started...");
    }

    public static void main(String[] args) throws IOException, InterruptedException {
    	
        Client client = new Client();
        
        System.out.println("My MAC: " + client.getMAC());
        System.out.println("My Disk ID: " + client.getDiskSN());
        System.out.println("My Motherboard ID: " + client.getMotherboardSN());

        LicenseManager licenseManager = new LicenseManager();
        
        System.out.println("Client -- " + (client.isLicenseExistent() ? "License file found" : "License file is not found"));
        
    	String info = client.getAllInfo();
        System.out.println("Client -- " + "Raw License Text: " + info);

        byte[] encrypted = client.encryptRSA(info.getBytes());
        System.out.println("Client -- " + "Encrypted License Text: " + new String(encrypted));

        String hashed = client.MD5(info);
        System.out.println("Client -- " + "MD5 License Text: " + hashed);
        
        if (client.isLicenseExistent()) {
            byte[] license = client.readFile("license.txt");
            boolean isValid = client.verifySignature(hashed.getBytes(),license);
            if (isValid) {
            	System.out.println("Client -- Succeed. The license is correct.");
            }
            else {
            	System.out.println("Client -- The license file has been broken!!");
            }
        	
        }
        
        else {
            licenseManager.runManager(encrypted);
            
            System.out.println("Client -- " + (client.isLicenseExistent() ? "License file found" : "License file is not found"));
            
            boolean isValid = client.verifySignature(licenseManager.hashed.getBytes(),licenseManager.signature);
            if (isValid) {
            	System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
            	client.writeFile(licenseManager.signature, "license.txt");
            }
            else {
            	System.out.println("Client -- The license file has been broken!!");
            }
        }

    }

    public void runApplication() throws IOException, InterruptedException {

    }

    public String getMAC() throws SocketException {
        String macHex = "";
        System.out.println();
        
        try {
            InetAddress ip = Inet4Address.getLocalHost(); // Get device ip
            NetworkInterface device = NetworkInterface.getByInetAddress(ip); // Get network interface name
            System.out.println(ip);
            System.out.println(device);
            byte[] mac = device.getHardwareAddress(); // Get mac address as a byte array
            macHex = bytesToHex(mac, ":");

        } catch (UnknownHostException | SocketException e) {
            e.printStackTrace();
            System.out.println("An error occurred on network configuration");
        }

        return macHex;
    }

    public String getDiskSN() throws IOException, InterruptedException { // TODO: Barış's part DONE
        // Get the disk serial number of the device
    	String disk_sn = null;
    	
		String OS = System.getProperty("os.name").toLowerCase();
		if (OS.contains("linux")) {
		    String sc = "/sbin/udevadm info --query=property --name=sda"; // get HDD parameters as non root user
		    String[] scargs = {"/bin/sh", "-c", sc};

		    Process p = Runtime.getRuntime().exec(scargs);
		    p.waitFor();

		    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream())); 
		    String line;
		    StringBuilder sb  = new StringBuilder();

		    while ((line = reader.readLine()) != null) {
		        if (line.indexOf("ID_SERIAL_SHORT") != -1) { // look for ID_SERIAL_SHORT or ID_SERIAL
		            sb.append(line);
		        }    
		    }
		    disk_sn = sb.toString().substring(sb.toString().indexOf("=") + 1);
		    return disk_sn;
		}
		else if (OS.contains("win")) {
			String sc = "cmd /c" + "wmic diskdrive get serialnumber";

		    Process p = Runtime.getRuntime().exec(sc);
		    p.waitFor();

		    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

		    String line;
		    StringBuilder sb = new StringBuilder();

		    while ((line = reader.readLine()) != null) {
		        sb.append(line);
		    } 

		    disk_sn =  sb.substring(sb.toString().lastIndexOf("r") + 1).trim();
		    return disk_sn;
		}
    	
		else {
			System.out.println("The program is incompatible with your operating system");
		}
		return disk_sn;
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

    // Returns all the info with "$" as separator
    public String getAllInfo() {
        return username+"$"+userSerialNumber+"$"+mac+"$"+DSN+"$"+MBSN;
    }
    
    
    /*
    public String getUsernameSerial() { // TODO: Barış's part DONE
        return username+"$"+userSerialNumber;
    }
    */

    public boolean isLicenseExistent() { // TODO: Barış's part
    	File f = new File("license.txt");
    	if(f.exists() && !f.isDirectory()) { 
    	    return true;
    	}
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
    public byte[] readFile(String path) {
        byte[] buf = new byte[0];
        try {
            BufferedInputStream stream = new BufferedInputStream(new FileInputStream(path));

            int byteCount = stream.available();
            buf = new byte[byteCount];

            int i = stream.read(buf);

            for (byte d : buf) {
                //System.out.println((char) d + ":" + d);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return buf;
    }

    public void writeFile(byte[] data, String path) {
        try(OutputStream os = new FileOutputStream(path)){
            for (byte b : data) {
                os.write(b);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
