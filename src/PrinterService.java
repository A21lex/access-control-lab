/**
 * Created by aleksandrs on 10/25/17.
 */

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;


public interface PrinterService extends Remote {


    public String echo(String input) throws RemoteException; //just test


    public String authenticate(String password, String username) throws IOException,
            NoSuchAlgorithmException; // long term authentication

    //Defined interface of the print server (String token added for authentication purposes)

    public String print(String token, String filename, String printer) throws RemoteException, FileNotFoundException;  // prints file filename on the specified printer

    public String queue(String token) throws RemoteException, FileNotFoundException;   // lists the print queue on the user's display in lines of the form <job number>   <file name>

    public String topQueue(String token, int job) throws RemoteException, FileNotFoundException;   // moves job to the top of the queue

    public String start(String token) throws RemoteException, FileNotFoundException;   // starts the print server

    public String stop(String token) throws RemoteException, FileNotFoundException;   // stops the print server

    public String restart(String token) throws RemoteException, FileNotFoundException;   // stops the print server, clears the print queue and starts the print server again

    public String status(String token) throws RemoteException, FileNotFoundException;  // prints status of printer on the user's display

    public String readConfig(String token, String parameter) throws RemoteException, FileNotFoundException;   // prints the value of the parameter on the user's display

    public String setConfig(String token, String parameter, String value) throws RemoteException, FileNotFoundException;   // sets the parameter to value

}
