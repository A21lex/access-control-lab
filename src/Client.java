/**
 * Created by aleksandrs on 10/25/17.
 */

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.security.NoSuchAlgorithmException;

public class Client {

    // a regular login and password stored by some client
    // hardcoded to avoid typing it in for every test of the code
    static String AliceLg = "Alice";
    static String AlicePw = "ali123";
    // Bob was removed from the company, so also removed his credentials from this file
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

    public static void main(String[] args) throws IOException, NotBoundException, NoSuchAlgorithmException {
        //checking the object reference by the name
        // ..some debugging here
        PrinterService service = (PrinterService) Naming.lookup("rmi://localhost:5099/printer");
        System.out.println("--- " + service.echo("hey server, i am CLIENT"));

        /* AUTHENTICATE SOME USER HERE BY INPUTTING PASSWORD AND LOGIN */
        String token = service.authenticate(HenryPw, HenryLg);
        System.out.println(token); // received authentication token

        // Invoke some methods and get the results of the invocation
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