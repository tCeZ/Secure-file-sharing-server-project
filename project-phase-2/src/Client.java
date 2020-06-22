import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedReader;      
import java.io.InputStreamReader; 

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
            final Socket sock = new Socket(server, port);
            System.out.println("Connected to " + server + " on port " +String.valueOf(port));
            
            final ObjectOutputStream output = new ObjectOutputStream(sock.getOutputStream());
            final ObjectInputStream input = new ObjectInputStream(sock.getInputStream());
            
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
            return false;
        }
        
        return isConnected();
       
        
        

		/* TODO: Write this method */

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
