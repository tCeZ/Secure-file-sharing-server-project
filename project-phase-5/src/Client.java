import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedReader;      
import java.io.InputStreamReader; 
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
    
    
    /*private String clientCommand()
    {
        try
        {
            System.out.println("Enter a line of text, or type \"EXIT\" to quit: ");	
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            return in.readLine();
        }
        catch(Exception e)
        {
            return "";
        }
        
    }*/

	public boolean connect(final String server, final int port) 
    {
		System.out.println("attempting to connect");
        try
        {
            sock = new Socket(server, port);
            System.out.println("Connected to " + server + " on port " +String.valueOf(port));
            
            output = new ObjectOutputStream(sock.getOutputStream());
            input = new ObjectInputStream(sock.getInputStream());
            
            /*Envelope msg = null, resp = null;
            
            while(!msg.getMessage().toUpperCase().equals("EXIT"))
            {
                msg = new Envelope(clientCommand());
                output.writeObject(msg);
                
                resp = (Envelope)input.readObject();
                System.out.println("\nServer says: " + resp.getMessage() + "\n");
            }
            
            disconnect();
            sock.close();*/
            
        }
        catch(Exception e)
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        
        return true;

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect(Key sessionKey)	 {
		if (isConnected()) {
			try
			{
                
				Envelope message = new Envelope("DISCONNECT");
                //message.addObject("DISCONNECTING");
                
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
                SecureRandom IV = new SecureRandom();
                byte IVarray[] = new byte[16];
                IV.nextBytes(IVarray);
                cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
                SealedObject outCipher = new SealedObject(message, cipher);
                // Create new Envelope with encrypted data and IV
                Envelope cipherMsg = new Envelope("ENV");
                Envelope encResponse = null;
                cipherMsg.addObject(outCipher);
                cipherMsg.addObject(IVarray);
                output.writeObject(cipherMsg);
				//output.writeObject(message);
                
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
    
    
}
