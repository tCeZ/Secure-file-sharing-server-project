/* Driver program for FileSharing File Server */

public class RunFileServer {
	
	public static void main(String[] args) {
		if (args.length > 0) {
			try {
                    if(args.length == 1)
                    {
                        FileServer server = new FileServer(Integer.parseInt(args[0]));
                        server.start();

                    }
                    else if(args.length == 3)
                    {
                        FileServer server = new FileServer(Integer.parseInt(args[0]), args[1], Integer.parseInt(args[2]));
                        server.start();
                        
                    }
                    else
                    {
                       System.out.printf("Enter a valid number of input or pass no arguments to use the default port (%d)\n", FileServer.SERVER_PORT); 
                    }
				
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", FileServer.SERVER_PORT);
			}
		}
		else {
			FileServer server = new FileServer();
			server.start();
		}
	}

}
