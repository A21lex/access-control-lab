/**
 * Created by aleksandrs on 10/25/17.
 */

import java.io.*;
import java.nio.file.Files;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.UUID;

public class PrinterServant extends UnicastRemoteObject implements PrinterService {


    private String currentUser; // stores user currently logged in

    protected PrinterServant() throws RemoteException {
        super();
    }

    public static String getHexStringFromBytes(byte[] arrayOfBytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayOfBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayOfBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    // looks up the hash of the salt + password for the given username
    private String lookupHash(String username) throws FileNotFoundException {
        Scanner sc = new Scanner(new FileReader("PublicUserFile"));
        String pattern = "=";
        String[] arr = null;
        sc.useDelimiter(pattern);
        while (sc.hasNext()) {
            String s = sc.nextLine();
            arr = s.split(pattern);
            if (arr[0].equals(username)) {
                return arr[1];
            }
        }
        return "unknown";
    }

    // looks up the salt for the given username
    private String lookupSalt(String username) throws FileNotFoundException {
        Scanner sc = new Scanner(new FileReader("PublicUserFile"));
        String pattern = "=";
        String[] arr = null;
        sc.useDelimiter(pattern);
        while (sc.hasNext()) {
            String s = sc.nextLine();
            arr = s.split(pattern);
            if (arr[0].equals(username)) {
                return arr[2];
            }
        }
        return "unknown";
    }

    private boolean tokenExists(String token) throws FileNotFoundException {
        Scanner sc = new Scanner(new FileReader("SecureTokenFile"));
        String pattern = "=";
        String[] arr = null;
        sc.useDelimiter(pattern);
        while (sc.hasNext()) {
            String s = sc.nextLine();
            arr = s.split(pattern);
            if (arr[1].equals(token)) {
                return true;
            }
        }
        return false;
    }

    // Generate a random token and store it in a secure file on the server side
    private String generateToken(String username) throws IOException {
        UUID uuid = UUID.randomUUID();
        String randomUuid = uuid.toString();
        // Check if username already in the file; if yes, remove the entire line
        deleteLineFromFile("SecureTokenFile", username);

        BufferedWriter writer = new BufferedWriter(new FileWriter("SecureTokenFile", true));
        writer.append(username);
        writer.append('=');
        writer.append(randomUuid);
        writer.append('\n');
        writer.close();
        return randomUuid;
    }

    private boolean deleteLineFromFile(String filename, String username) throws IOException {
        String tempFileName = "TempSecureTokenFile";
        File inputFile = new File(filename);
        File tempFile = new File(tempFileName);
        FileInputStream fileInputStream = new FileInputStream(inputFile);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream));
        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(tempFileName, true));
        //System.out.println("Starting deleting lines starting with " + username);
        String line = null;
        while ((line = bufferedReader.readLine()) != null) {
            //System.out.println("While loop works"); //debug
            //System.out.println("current line: " + line); //debug
            if (!line.startsWith(username)) {
                //System.out.println("line " + line + " should be preserved");
                bufferedWriter.append(line);
                bufferedWriter.append('\n');
            }
        }
        bufferedWriter.close();
        bufferedReader.close();

        try {
            Files.move(new File(tempFileName).toPath(), new File(filename).toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return tempFile.renameTo(inputFile);
    }

    /**
     * Checks whether method execution is allowed by acl
     *
     * @param methodName The name of the method which is being invoked
     * @param username   The name of the user trying to invoke a method
     * @return True for allowed, False for forbidden
     */
    private boolean isAllowed(String methodName, String username) throws FileNotFoundException {
        Scanner sc = new Scanner(new FileReader("acl"));
        String patternUsername = ":";
        String patternMethodName = ";";
        String[] arr = null;
        sc.useDelimiter(patternUsername);
        while (sc.hasNext()) {
            String s = sc.nextLine();
            arr = s.split(patternUsername);
            //PRINT ARRAY OF USER PERMISSIONS FOR DEBUGGING PURPOSES
            System.out.println("PRINT ARRAY 1");
            for (int i = 0; i < arr.length; i++) {
                System.out.println(arr[i]);
            }
            if (arr[0].equals(username)) {
                // Check for "all" permission - allows every system action
                if (arr[1].equals("all")) {
                    return true;
                }
                sc.useDelimiter(patternMethodName); // change delimiter to ; to go through permissions
                arr = arr[1].split(patternMethodName); // arr[1] here is the list of permissions for current user
                System.out.println("PRINT ARRAY 2");
                //PRINT ARRAY OF PERMISSION FOR DEBUGGING PURPOSES
                for (int i = 0; i < arr.length; i++) {
                    System.out.println(arr[i]);
                }
                return Arrays.asList(arr).contains(methodName); //return true if it contains needed permission
            }
        }
        return false;
    }

    @Override
    public String echo(String input) throws RemoteException {
        return "I, SERVER, have received the input: " + input; // returning input given by the client
    }

    @Override
    public String authenticate(String password, String username) throws IOException,
            NoSuchAlgorithmException {
        currentUser = username; // remember the username of the currently logged in user
        System.out.println("Attempting to log in user with presumed login: " + currentUser);

        // 1. Get the user's salt/hash from the database

        String lookedUpHash = lookupHash(username); // look up the hash for the given username
        String lookedUpSalt = lookupSalt(username); // and the salt..

        // 2. Prepend the salt to the received password and hash it

        String saltPass = lookedUpSalt + password;
        byte SaltPassBytes[] = saltPass.getBytes(); // resultant salt+pass bytes

        // hash the salt+given password
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(SaltPassBytes);
        byte byteData[] = md.digest();
        //Convert byte to hex
        String saltPasswordHash = getHexStringFromBytes(byteData);
        System.out.println("Hex format of the hashed salt+pw: " + saltPasswordHash);

        // 3. Check whether hash corresponds to the one given in the text file for the given username

        if (saltPasswordHash.equals(lookedUpHash)) {
            System.out.println("Authenticaiton successful. Generating token.");
            return generateToken(username);
            //return "Authentication successful";
        }

        return "Authentication failed. Password not matching. Received the following: " + saltPasswordHash;
    }

    @Override
    public String print(String token, String filename, String printer) throws RemoteException, FileNotFoundException {
        // Get the name of the method currently being executed
        class Local {}
        String methodName = Local.class.getEnclosingMethod().getName();
        System.out.println(methodName + " <<<METHOD NAME"); // just debug
        // Check whether method execution is allowed for the current user
        if (!isAllowed(methodName, currentUser)) {
            return "ACL gives no permission to use this method for user " + currentUser + ". Printer will not start";
        }

        if (!tokenExists(token)) {
            return "No token detected. Printer will not start.";
        }
        return "print successfully invoked, token " + token + " exists and permission is given.";
    }

    @Override
    public String queue(String token) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "queue successfully invoked, token " + token + " exists";
        }
        return "No token detected. Queue will not be invoked.";
    }

    @Override
    public String topQueue(String token, int job) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "topQueue successfully invoked, token " + token + " exists";
        }
        return "No token detected. topQueue will not start";
    }

    @Override
    public String start(String token) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "start successfully invoked, token " + token + " exists";
        }
        return "No token detected. Printer will not start";
    }

    @Override
    public String stop(String token) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "stop successfully invoked, token " + token + " exists";
        }
        return "No token detected. Printer will not stop";
    }

    @Override
    public String restart(String token) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "restart successfully invoked, token " + token + " exists";
        }
        return "No token detected. Printer will not restart";
    }

    @Override
    public String status(String token) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "status successfully invoked, token " + token + " exists";
        }
        return "No token detected. Status will not start";
    }

    @Override
    public String readConfig(String token, String parameter) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "status successfully invoked, token " + token + " exists";
        }
        return "No token detected. Status will not start";
    }

    @Override
    public String setConfig(String token, String parameter, String value) throws RemoteException, FileNotFoundException {
        if (tokenExists(token)) {
            return "setConfig successfully invoked, token " + token + " exists";
        }
        return "No token detected. setConfig will not start";
    }
}
