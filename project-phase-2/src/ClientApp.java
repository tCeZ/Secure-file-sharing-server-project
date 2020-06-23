import java.util.Scanner;
import java.util.Arrays;
import java.util.List;


public static void main(String[] args) {
	
	//main classes for the app
	GroupClient g = new GroupClient();
	Fileclient f = new FileClient();
	Scanner s = new Scanner(System.in);

	boolean conn = true; //boolean for multiple logins
	UserToken usrT = null; // token to verify users
	String hostN;
	String userN;
	String groupN;
	String input;
	int mchoice;
	boolean tokencheck = false;
	List<String> listmems = null;


	while(conn)
	{
		// connect to the only one group server lol
		// ask for server IP
		System.out.println(“Enter IP Address or Hostname of the Group Server: \n”);
		hostN = s.nextLine();

		System.out.println(“Enter your username for the specified server: \n”);
		userN = s.nextLine();

		//connect to the specified hostname and hard port
		g.connect(hostN, 8765);
		if (gc.isConnected())
		{
			usrT = g.getToken(userN);
			if (usrT != null)
			{
				tokencheck = true;
				g.disconnect();
			}
			//did not find a token for that username - uh-roh
			else 
			{
				System.out.println(“Username is invalid.”);
				g.disconnect();
			}
		}
		else
		{
			System.out.println(“Failed to connect to %s - Group Server”,hostN );
		}

		//connecting to server if token was verified
		while(tokencheck)
		{
			System.out.println(“Main menu: \n” + 
								“Enter 1 to connect to a File Server \n” + 
								"Enter 2 to create user \n " +
								"Enter 3 to delete user \n " + 
								"Enter 4 to create group \n " +
								"Enter 5 to delete group \n " + 
								"Enter 6 to add user to group \n " +
								"Enter 7 to delete user from group \n " +
								"Enter 8 to listMembers \n " +
								“Enter 0 to logout:  \n” + userN + “: “);

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
					System.out.println(“Enter the port number of the File Server \n” + userN + “: ”);
					portN = s.nextLine();
					portN = Integer.parseInt(portN);

					//get hostname or IP of file server
					System.out.println("Enter IP Address or Hostname of the File Server: \n" + userN + “: ”);
					fshostN = s.nextLine();
					

					//file server menu
					if (f.connect())


				case 2: 

					//check to see if admin
					if (usrT.getGroups().contains("ADMIN"))
					{
						System.out.println("Username to create" + userN + “: ”);
						userN = s.nextLine();

						if(g.createUser(userN, usrT))
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
						System.out.println("Username to delete" + userN + “: ”);
						userN = s.nextLine();

						if(g.deleteUser(userN, usrT))
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
						System.out.println("Group name to create:" + userN + “: ”);
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
						System.out.println("Group name to create:" + userN + “: ”);
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

					System.out.println("Group name: " + userN + ": ")
					groupN = s.nextLine();

					System.out.println("User name to add to group:" + userN + “: ”);
					userN = s.nextLine();

					if(g.addUserToGroup(userN, groupN, usrT))
					{
						System.out.println("Added user to group!");
					}
					else
					{
						System.out.println("Failed to add user to group");
					}
					
					break;

				case 7: 

					System.out.println("Group name: " + userN + ": ");
					groupN = s.nextLine();

					System.out.println("User name to delete to group:" + userN + ": ");
					userN = s.nextLine();

					if(g.deleteUserFromGroup(userN, groupN, usrT)
					{
						System.out.println("Removed user to group!");
					}
					else
					{
						System.out.println("Failed to remove user from group!");
					}

					break;

				case 8: 

					System.out.println("Group name: " + userN + ": ");
					groupN = s.nextLine();

					listmems = listMembers(groupN, usrT);

					if (listmems != null)
					{
						System.out.println(listMembers);
					}
					else
					{
						System.out.println("Failed to list members - check to make sure you are part of group");
					}

					break;

				case 0: 

					System.out.println("Logging out!");
					tokencheck = false; 
					usrT = null; 
					break;

				default: 
					System.out.println("Unidentifiable command. Please enter a valid command");
					break;

			}
			
		}
	}
		

            
}
