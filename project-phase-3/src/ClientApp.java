import java.util.Scanner;
import java.util.List;
import java.util.Arrays;
import java.io.*;
import java.security.*;
import java.lang.*;

public class ClientApp
{

    public static void main(String[] args) 
    {
        
        //main classes for the app
        GroupClient g = new GroupClient();
        FileClient f = new FileClient();
        Scanner s = new Scanner(System.in);

        boolean conn = true; //boolean for multiple logins
        UserToken usrT = null; // token to verify users
        String hostN;
        String userN;
        String userNN;
        String groupN = new String();
        String input;
        int mchoice;
        int portN;
        String fshostN;
        boolean tokencheck = false;
        List<String> listmems = null;
        List<String> listfiles = null;
        String tokenUser = null;


        while(conn)
        {
            // connect to the only one group server lol
            // ask for server IP
            System.out.print("Enter IP Address or Hostnmae of the Group Server: ");
            hostN = s.nextLine();

            System.out.print("Enter your username for the specified server: ");
            userN = s.nextLine();

            //connect to the specified hostname and hard port
            g.connect(hostN, 8765);
            if (g.isConnected())
            {
                // get the session key
                if (g.getSessionKey()) {
                    System.out.println("Obtained the session key for this session. Connection is secured");
                 }
                 else {
                    System.out.println("Failed in obtaining the session key. Connection not secured");
                 }   
                tokenUser = null;
                System.out.print("Whose token are you trying to request: ");
                tokenUser = s.nextLine();
                usrT = g.getToken(userN,tokenUser);
                if (usrT != null)
                {
                    tokencheck = true;
                    tokenUser = userN;
                    
                }
                //did not find a token for that username - uh-roh
                else 
                {
                    System.out.println("Permission denied");
                    g.disconnect();
                        
                }
            }
            
            else
            {
                System.out.println("Failed to connect to Group Server");

            }

            //connecting to server if token was verified
            while(tokencheck)
            {
                usrT = g.getToken(userN,tokenUser);
                System.out.print( "Main Menu: \n " +
                                    "Enter 1 to connect to File Server \n " + 
                                    "Enter 2 to create user \n " +
                                    "Enter 3 to delete user \n " + 
                                    "Enter 4 to create group \n " +
                                    "Enter 5 to delete group \n " + 
                                    "Enter 6 to add user to group \n " +
                                    "Enter 7 to delete user from group \n " +
                                    "Enter 8 to listMembers \n " +
                                    "Enter 0 to logout: \n " +
                                     userN + ": "); 

                input = s.nextLine();

                try
                {
                    mchoice = Integer.parseInt(input);
                }
                catch (Exception e)
                {
                    mchoice = -1;
                }

                switch (mchoice)
                {
                    case 1:
                        //get port of file server
                        System.out.print("Enter the port number of the File Server: ");
                        //System.out.println("Enter the port number of the File Server \n” + userN ": ");
                        input = s.nextLine();
                        portN = Integer.parseInt(input);

                        //get hostname or IP of file server
                        System.out.print("Enter IP Address or Hostname of the File Server: ");
                        fshostN = s.nextLine();
                        

                        //file server menu
                        if (f.connect(fshostN, portN))
                        {
                            boolean conn2 = true;
                            int mchoice2;
                            String uploadfile;
                            String dest;
                            String downloadf;
                            String delf;
                            String groupShare;
                            String fsFile = "FileServerList.bin";
                            ObjectInputStream ois;
                            PublicKey fsKey = f.getPubKey();
                            FileServerID fsID = new FileServerID(fshostN,portN,fsKey);

                            try {
                                FileInputStream fis = new FileInputStream(fsFile);
                                ois = new ObjectInputStream(fis);
                                FileServerList fsList = (FileServerList)ois.readObject();
                                ois.close();
                                fis.close();

                                if (fsList.hasServer(fsID)) {
                                    System.out.println("File Server has been used before. Connected.");
                                }
                                else {
                                    System.out.println("File Server has not been used before. Add it.");

                                    String answer = getNonEmptyString("> ", 32);
                                    if (answer.charAt(0) == 'y' || answer.charAt(0) == 'Y') {
                                        FileOutputStream fos;
                                        ObjectOutputStream oos;
                                        try {
                                            FileServerList fsl = new FileServerList();
                                            fsl.addServer(fsID);
                                            fos = new FileOutputStream(fsFile);
                                            oos = new ObjectOutputStream(fos);
                                            oos.writeObject(fsl);
                                            oos.close();
                                            fos.close();
                                            System.out.println("File Server added to trusted server list.");
                                        }
                                        catch(Exception ee) {
                                            System.err.println("Error writing to " + fsFile + ".");
                                            ee.printStackTrace(System.err);
                                            System.exit(-1);
                                        }
                                    }
                                    else {
                                        System.out.println("Server will not be added. Exiting.");
                                        conn = false;
                                    }
                                }
                            }
                            catch(FileNotFoundException e) {
                                System.out.println("File Server List Does Not Exist. Creating " + fsFile + "...");
                                FileOutputStream fos;
                                ObjectOutputStream oos;
                                try {
                                    FileServerList fsl = new FileServerList();
                                    fsl.addServer(fsID);
                                    fos = new FileOutputStream(fsFile);
                                    oos = new ObjectOutputStream(fos);
                                    oos.writeObject(fsl);
                                    oos.close();
                                    fos.close();
                                }
                                catch(Exception ee) {
                                    System.err.println("Error writing to " + fsFile + ".");
                                    ee.printStackTrace(System.err);
                                    System.exit(-1);
                                }                               
                            }
                            catch(IOException e) {
                                System.out.println("Error reading from " + fsFile);
                                System.exit(-1);
                            }
                            catch(ClassNotFoundException e) {
                                System.out.println("Error reading from UserList file");
                                System.exit(-1);
                            }

                            if (f.getSessionKey()) {
                                System.out.println("Obtained the session key for this session. Connection is secured");
                            }
                            else {
                                System.out.println("Failed in obtaining the session key. Connection not secured");
                                conn2 = false;
                            }                            
                


                            while(conn2)
                            {
                                System.out.print(
                                     " Enter 1 to list Files in the Server \n " +
                                     "Enter 2 to upload file \n " +
                                     "Enter 3 to download file \n " +
                                     "Enter 4 to delete a file from the File Server \n " +
                                     "Enter 0 to disconnect from File Server \n " +
                                     userN + ": ");

                                input = s.nextLine();

                                try
                                {
                                    mchoice2 = Integer.parseInt(input);
                                }
                                catch(Exception e)
                                {
                                    mchoice2 = -1; 
                                }

                                switch (mchoice2)
                                {
                                    case 1: 

                                        listfiles = f.listFiles(usrT,g.getUserList());
                                        if (listfiles != null && listfiles.size() != 0)
                                        {
                                            for (String fs: listfiles)
                                            {
                                                System.out.println(fs);
                                            }
                                        }
                                        else
                                        {
                                            System.out.println("No files exist");
                                        }

                                        break;

                                    case 2: 

                                        System.out.print("Path to file for upload: " ); // format: ./test.txt (if file is in the src folder, otherwise ./../.../name)
                                        uploadfile = s.nextLine();

                                        System.out.print("Name for file to be shown on file server: ");
                                        dest = s.nextLine();
                                        
                                        System.out.print("Name of the group to share with: ");
                                        groupShare = s.nextLine();
                                        if (f.upload(uploadfile, dest, groupShare, usrT, g.getUserList()))
                                        {
                                            System.out.println("Successfully uploaded file");
                                        }
                                        else
                                        {
                                            System.out.println("Failed to upload");
                                        }

                                        break;

                                    case 3: 

                                        System.out.print("Name of file on file list to be downloaded: " );
                                        downloadf = s.nextLine();

                                        System.out.print("Name of file to shown on local: ");
                                        dest = s.nextLine();

                                        if (f.download(downloadf, dest, usrT, g.getUserList()))
                                        {
                                            System.out.println("Sucessfully downloaded file");
                                        }
                                        else
                                        {
                                            System.out.println("Failed to download file");
                                        }

                                        break;

                                    case 4: 

                                        System.out.print("Filename to be deleted: ");
                                        delf = s.nextLine();

                                        if (f.delete(delf, usrT, g.getUserList()))
                                        {
                                            System.out.println("Sucessfully deleted file");
                                        }
                                        else
                                        {
                                            System.out.println("Failed to delete file");
                                        }

                                        break;

                                        
                                    case 0: 

                                        System.out.println("Logging out!");
                                        f.disconnect();
                                        conn2 = false;
                                        break;

                                    default: 

                                        System.out.println("Unidentifiable command. Please enter a valid command");
                                        break;

                                }
                            }
                        }
                        else
                        {
                            System.out.println("Error connecting to File Server. Try Again.");
                        }
                        break;


                    case 2: 

                        //check to see if admin
                        if (usrT.getGroups().contains("ADMIN"))
                        {
                            System.out.print("Username to create: ");
                            userNN = s.nextLine();

                            if(g.createUser(userNN, usrT))
                            {
                                System.out.println("Created User!");
                            }
                            else
                            {
                                System.out.println("Failed to create User");
                            }
                        }

                        break;

                    case 3:

                        //check to see if admin
                        if (usrT.getGroups().contains("ADMIN"))
                        {
                            System.out.print("Username to delete: ");
                            userNN = s.nextLine();

                            if(g.deleteUser(userNN, usrT))
                            {
                                System.out.println("Deleted User!");
                            }
                            else
                            {
                                System.out.println("Failed to delete User");
                            }
                        }

                        break;

                    case 4:

                        //check to see if admin
                        if (usrT.getGroups().contains("ADMIN"))
                        {
                            System.out.print("Group name to create: ");
                            groupN = s.nextLine();

                            if(g.createGroup(groupN, usrT))
                            {
                                System.out.println("Created Group!");
                            }
                            else
                            {
                                System.out.println("Failed to create Group!");
                            }
                        }

                        break;

                    case 5: 

                        //check to see if admin
                        if (usrT.getGroups().contains("ADMIN"))
                        {
                            System.out.print("Group name to create: ");
                            groupN = s.nextLine();

                            if(g.deleteGroup(groupN, usrT))
                            {
                                System.out.println("Deleted Group!");
                            }
                            else
                            {
                                System.out.println("Failed to delete Group!");
                            }
                        }

                        break;

                    case 6: 

                        System.out.print("Group name: ");
                        groupN = s.nextLine();

                        System.out.print("User name to add to group: ");
                        userNN = s.nextLine();

                        if(g.addUserToGroup(userNN, groupN, usrT))
                        {
                            System.out.println("Added user to group!");
                        }
                        else
                        {
                            System.out.println("Failed to add user to group");
                        }
                        
                        break;

                    case 7: 

                        System.out.print("Group name: ");
                        groupN = s.nextLine();

                        System.out.print("User name to delete to group: ");
                        userNN = s.nextLine();

                        if(g.deleteUserFromGroup(userNN, groupN, usrT))
                        {           
                            System.out.println("Removed user to group!");
                        }
                        else
                        {
                            System.out.println("Failed to remove user from group!");
                        }

                        break;

                    case 8: 

                        System.out.print("Group name: ");
                        groupN = s.nextLine();

                        listmems = g.listMembers(groupN, usrT);

                        if (listmems != null)
                        {
                            System.out.println(listmems);
                        }
                        else
                        {
                            System.out.println("Failed to list members - check to make sure you are part of group! - check your Token!");
                        }

                        break;

                    case 0: 

                        System.out.println("Logging out!");
                        tokencheck = false; 
                        conn = false;
                        usrT = null; 
                        break;

                    default: 

                        System.out.println("Unidentifiable command. Please enter a valid command!");
                        break;
                }
            }       
        }
                
    }

    public static String getNonEmptyString(String prompt, int maxLength) {
        String str = "";
        Scanner scan = new Scanner(System.in);
        
        System.out.print(prompt);        
        
        while (str.length() == 0) {
            str = scan.nextLine();
            
            if (str.length() == 0) {
                System.out.print(prompt);
            }
            else if (str.length() > maxLength) {
                System.out.println("Maximum length allowed is " + maxLength + " characters. Please re-enter.");
                System.out.print(prompt);
                str = "";
            }
        }
        
        return str;
    }
    
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
    
    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        
        int len = block.length;
        
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}


