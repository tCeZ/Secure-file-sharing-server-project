/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.io.*;
import javax.crypto.spec.IvParameterSpec;
import java.lang.*;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
                    if(message.getObjContents().size() < 2)
                    {
                        response = new Envelope("FAIL");
                        
                    }
                    else
                    {
                        response = new Envelope("FAIL");
                        
                        if(message.getObjContents().get(0) != null)
                        {
                            if(message.getObjContents().get(1) != null)
                            {
                               String groupname = (String)message.getObjContents().get(0); //Extract the groupname
                               UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                               
                               if(createGroup(groupname, yourToken))
                               {
                                   response = new Envelope("OK");
                               }
                            }
                            
                            
                        }
                    }
                    output.writeObject(response);
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
                    if(message.getObjContents().size() < 2)
                    {
                        response = new Envelope("FAIL");
                    }
                    else
                    {
                        response = new Envelope("FAIL");
                        
                        if(message.getObjContents().get(0) != null)
                        {
                            if(message.getObjContents().get(1) != null)
                            {
                                String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                
                                if(deleteGroup(groupname, yourToken))
                                {
                                    response = new Envelope("OK");
                                }
                            }
                        }
                    }
                    output.writeObject(response);
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
                    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
                    else
                    {
                        response = new Envelope("FAIL");
                        
                        if(message.getObjContents().get(0) != null)
                        {
                            if(message.getObjContents().get(1) != null)
                            {
                                String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                ArrayList<String> memberList = new ArrayList<String>();
                                memberList = listMembers(groupname, yourToken);
                                
                                if(memberList != null)
                                {
                                    response = new Envelope("OK");
                                    response.addObject(memberList);
                                }
                            }
                        }
                    }
                    output.writeObject(response);
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
                    if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
                    else
                    {
                        response = new Envelope("FAIL");
                        
                        if(message.getObjContents().get(0) != null)
                        {
                            if(message.getObjContents().get(1) != null)
                            {
                                if(message.getObjContents().get(2) != null)
                                {
                                    String username = (String)message.getObjContents().get(0); //Extract the username
                                    String groupname = (String)message.getObjContents().get(1); //Extract the groupname
								    UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
                                    
                                    if(addUserToGroup(username, groupname, yourToken))
                                    {
                                        response = new Envelope("OK");
                                    }
                                }
                            }
                        }
                        
                        
                    }
                    output.writeObject(response);
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
                    if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
                    else
                    {
                        response = new Envelope("FAIL");
                        if(message.getObjContents().get(0) != null)
                        {
                            if(message.getObjContents().get(1) != null)
                            {
                                if(message.getObjContents().get(2) != null)
                                {
                                    String username = (String)message.getObjContents().get(0); //Extract the username
                                    String groupname = (String)message.getObjContents().get(1); //Extract the groupname
								    UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
                                    
                                    if(deleteUserFromGroup(username, groupname, yourToken))
                                    {
                                        response = new Envelope("OK");
                                    }
                                }
                            }
                        }
                    }
                    output.writeObject("OK");
                    
                    
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
    
    private boolean createGroup(String groupname, UserToken yourToken)
    {
        String requester = yourToken.getSubject();
        
        if(my_gs.userList.checkUser(requester))
        {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            if(temp.contains(groupname))
            {
                return false;
            }
            else
            {
                my_gs.userList.addGroup(requester, groupname);
                my_gs.userList.addOwnership(requester, groupname);
                return true;
            }
            
        }
        else
        {
            return false;
        }
    }
    
    private boolean deleteGroup(String groupname, UserToken yourToken)
    {
        String requester = yourToken.getSubject();
        
        if(my_gs.userList.checkUser(requester))
        {
            ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
            
            
            if(temp.contains(groupname)) // check ownership of the group
            {
                my_gs.userList.removeGroup(requester, groupname); // remove group from owner's list
                my_gs.userList.removeOwnership(requester, groupname); // remove group ownership from owner
                
                ArrayList<String> temp2 = my_gs.userList.getAllUsers(); // get all user information
                for(int i = 0; i < temp2.size(); i++) // loop
                {
                    if(my_gs.userList.getUserGroups(temp2.get(i)).contains(groupname)) // check whether deleted group is in each user's group list
                    {
                        my_gs.userList.removeGroup(temp2.get(i), groupname); // delete group from that user's group list
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    
    private ArrayList<String> listMembers(String groupname, UserToken yourToken)
    {
        String requester = yourToken.getSubject();
        
        if(my_gs.userList.checkUser(requester))
        {
            ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
            
            
             if(temp.contains(groupname))
             {
                ArrayList<String> temp2 = my_gs.userList.getAllUsers(); // get all user information
                ArrayList<String> temp3 = new ArrayList<String>();
                
                
                for(int i = 0; i < temp2.size(); i++) // loop
                {
                    if(my_gs.userList.getUserGroups(temp2.get(i)).contains(groupname)) // check whether deleted group is in each user's group list
                    {
                       temp3.add(temp2.get(i));
                    }
                }
                return temp3;
                
             }
             else
             {
                 return null;
             }
            
        }
        else
        {
            return null;
        }
    }
    
    private boolean addUserToGroup(String username, String groupname, UserToken yourToken)
    {
        String requester = yourToken.getSubject();
        
        if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username))
        {
            ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
            
            if(temp.contains(groupname) && !my_gs.userList.getUserGroups(username).contains(groupname))
            {
                ArrayList<String> temp2 = my_gs.userList.getAllUsers();
                for(int i = 0; i < temp2.size(); i++)
                {
                    if(temp2.get(i).equals(username))
                    {
                        my_gs.userList.addGroup(username, groupname);
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    
    private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken)
    {
        String requester = yourToken.getSubject();
        
        if(my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(username))
        {
            ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
            if(temp.contains(groupname) && my_gs.userList.getUserGroups(username).contains(groupname))
            {
                
                if(username == requester)
                {
                    deleteGroup(groupname, yourToken);
                    return true;
                }
                
                ArrayList<String> temp2 = my_gs.userList.getAllUsers();
                
                for(int i = 0; i < temp2.size(); i++)
                {
                    if(temp2.get(i).equals(username))
                    {
                        my_gs.userList.removeGroup(username, groupname);
                    }
                    
                }
                return true;
                
                
                
                
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
        
    }
}
