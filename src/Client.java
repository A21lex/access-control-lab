/**
 * Created by aleksandrs on 10/25/17.
 */

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.security.NoSuchAlgorithmException;

public class Client {

    //a regular login and password stored by some client
    //assume some server stores hashed password of every user (did it during user registration)
    static String AliceLg = "Alice";
    static String AlicePw = "ali123";
    static String BobLg = "Bob";
    static String BobPw = "boxy123";
    static String CeciliaLg = "Cecilia";
    static String CeciliaPw = "ceci123";
    static String DavidLg = "David";
    static String DavidPw = "dav123";
    static String EricaLg = "Erica";
    static String EricaPw = "eri123";
    static String FredLg = "Fred";
    static String FredPw = "fre123";
    static String GeorgeLg = "George";
    static String GeorgePw = "geo123";



    public static String getHexStringFromBytes(byte[] arrayOfBytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayOfBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayOfBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    public static void main(String[] args) throws IOException, NotBoundException, NoSuchAlgorithmException {
        //checking the object reference by the name
        // ..some debugging here
        PrinterService service = (PrinterService) Naming.lookup("rmi://localhost:5099/printer");
        System.out.println("--- " + service.echo("hey server, i am CLIENT"));

        //THIS WOULD BE IMPLEMENTED FOR SALT GENERATION
        // (and was used to generate salts for the users within this exercise)
//
//        SecureRandom random = new SecureRandom();
//        byte saltBytes[] = new byte[64];
//        // generate random 64 bytes
//        random.nextBytes(saltBytes);
//        String generatedSalt = getHexStringFromBytes(saltBytes);
//        System.out.println("Randomly generated salt: " + generatedSalt);
//
//
//        String saltAndPassword = generatedSalt + AlicePw;
//
//        byte saltAndPasswordBytes[] = saltAndPassword.getBytes();
//        //do some hashing initialization and process the password
//        MessageDigest md = MessageDigest.getInstance("SHA-512");
//        md.update(saltAndPasswordBytes); // hash the salt+password
//        byte byteData[] = md.digest();
//        //Convert byte to hex
//        String passwordHash = getHexStringFromBytes(byteData);
//        System.out.println("Hash of Salt + password in bytes: " + passwordHash);

        //String token = service.authenticate(AlicePw, AliceLg);
        String token = service.authenticate(AlicePw, AliceLg);
        System.out.println(token);

        String printerOutput = service.print(token, "testFile", "testPrinter");
        System.out.println(printerOutput);

        System.out.println(service.queue(token));
        System.out.println(service.start(token));
        System.out.println(service.topQueue(token, 0));
        System.out.println(service.stop(token));
        System.out.println(service.restart(token));
        System.out.println(service.status(token));
        System.out.println(service.readConfig(token, null));
        System.out.println(service.setConfig(token, null, null));

    }

}