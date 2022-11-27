import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Client {
    public Client() {

    }

    public static void main(String[] args) {
        Client client = new Client();

        // retrieve network interface's MAC address
        String mac = client.getMAC();
        System.out.println("mac = " + mac);

        // Retrieve disk serial number


        // Retrieve motherboard's serial number
        String MBSN = client.getMotherboardSN();

    }

    public String getMAC() {
        StringBuilder builder = new StringBuilder();

        try {
            InetAddress ip = Inet4Address.getLocalHost(); // Get device ip
            NetworkInterface device = NetworkInterface.getByInetAddress(ip); // Get network interface name

            byte[] mac = device.getHardwareAddress(); // Get mac address as a byte array
            builder = new StringBuilder();

            for (int i = 0; i < mac.length; i++) { // Parse bytes to hex string
                String hex = Integer.toHexString(mac[i]);
                hex = hex.substring(hex.length() - 2); // Get last two characters (for 2's complement bytes)
                builder.append(hex);

                if (i < mac.length - 1) {
                    builder.append(":");
                }
            }
        } catch (UnknownHostException | SocketException e) {
            e.printStackTrace();
            System.out.println("An error occurred on network configuration");
        }

        return builder.toString();
    }

    public String getDiskSN() { // TODO: Barış'ın işi
        return null;
    }

    public String getMotherboardSN() { // TODO: Fix this
        String OS = System.getProperty("os.name").toLowerCase(); // OS name
        String sn = null; // Serial number to return

        try {
            // Decide the command based on the operating system
            String[] cmd = {}; // Calling exec with a string parameter is deprecated
            if (OS.contains("linux")) { // Linux
                cmd = new String[]{"sudo dmidecode -s baseboard-serial-number"};
            } else if (OS.contains("win")) { // Windows
                cmd = new String[]{"wmic baseboard get serialnumber"};
            } else {
                System.out.println("The program is incompatible with your operating system");
            }

            System.out.println("cmd = " + Arrays.toString(cmd));
            Process serialNumberProcess = Runtime.getRuntime().exec(cmd);
            InputStreamReader ISR = new InputStreamReader(serialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);
            sn = br.readLine(); // todo trim

            serialNumberProcess.waitFor();

            System.out.println("sn = " + sn);

        } catch (Exception e) {

        }

        return null;

    }
}
