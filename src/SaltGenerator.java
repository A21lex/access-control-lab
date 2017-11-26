/**
 * Created by aleksandrs on 11/22/17.
 */

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class was used for salt generation
 */
public class SaltGenerator {

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

    // Users added after the changes
    static String HenryLg = "Henry";
    static String HenryPw = "henry123";

    static String IdaLg = "Ida";
    static String IdaPw = "ida123";


    public static String getHexStringFromBytes(byte[] arrayOfBytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayOfBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayOfBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
//        THIS WOULD BE IMPLEMENTED FOR SALT GENERATION
//         (and was used to generate salts for the users within this exercise)

        SecureRandom random = new SecureRandom();
        byte saltBytes[] = new byte[64];
        // generate random 64 bytes
        random.nextBytes(saltBytes);
        String generatedSalt = getHexStringFromBytes(saltBytes);
        System.out.println("Randomly generated salt: " + generatedSalt);


        String saltAndPassword = generatedSalt + IdaPw; // put a password to get a salt for

        byte saltAndPasswordBytes[] = saltAndPassword.getBytes();
        //do some hashing initialization and process the password
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(saltAndPasswordBytes); // hash the salt+password
        byte byteData[] = md.digest();
        //Convert byte to hex
        String passwordHash = getHexStringFromBytes(byteData);
        System.out.println("Hash of Salt|password in bytes: " + passwordHash);

    }


}