import java.io.*;
import java.net.*;
import java.security.*;

// TODO: Görev dağılımını todo'lar ile yaptım, oradan bakarak yapabilirsin.

/*

    Run the program as "java Client.java from console if you are using Linux

*/

public class Client {
    public Client() {

    }

    public static void main(String[] args) {
        Client client = new Client();

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
//                cmd = "pwd";
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

    public byte[] encryptRSA() { // TODO Buğrahan's part
        StringBuilder sb = new StringBuilder();

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


}
