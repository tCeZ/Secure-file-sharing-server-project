# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java -cp .:bcprov-jdk15on-165.jar RunGroupServer`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java -cp .:bcprov-jdk15on-165.jar RunFileServer`

Note that the port number argument to `RunFileServer is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Resetting the Group or File Server

To reset the Group Server, delete the file `UserList.bin`

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.


## Running the Client Application
- Enter the directory containing 'ClientApp.class'
- Type 'java -cp .:bcprov-jdk15on-165.jar ClientApp'

The Group Server:
The operations that user can do are shown on terminal in terms of number for etc: 1. getToken 2.createUser (User can choose the operation and then input required information to continue)

1.boolean connect(String server, int port)
Ask user for the port number and server name or use the default one and then try to connect them to the group server(when they try to log in)

2.void disconnect()
If user input is disconnect or they shutdown the terminal, then the disconnect functionality will be triggered

3.UserToken getToken(String username)
User get token by input username

4.boolean createUser(String username, UserToken token)
User with priority can new user by providing token and new username through terminal

5.boolean deleteUser(String username, UserToken Token)
User with priority can delete other user by providing token and username through terminal

6.boolean createGroup(String groupname, UserToken token)
User can create new group by providing new group name and token through terminal

7.boolean deleteGroup(String groupname, UserToken token)
User can delete the existing group by providing group name and token through terminal

8.boolean addUserToGroup(String user, String group, UserToken token)
User who is the owner of the group can add other user to his or her group by providing username of that user he wants to add, group name and token through terminal

9.deleteUserFromGroup(String user, String group, userToken token)
User who is the owner of the group can delete other user from group by providing username of that user he wants to delete, group name and token through terminal

10.List<String> listMembers(String group, UserToken token)
User who is the owner of the group can list members in group by providing group name and token through terminal




The File Server:
The operations that user can do are shown on terminal in terms of number for etc: 1.upload 2.delete (User can choose the operation and then input required information to continue)

1.boolean connect(String server, int port)
Ask user for the port number and server name or use the default one and then try to connect them to the group server(when they try to log in)

2.void disconnect()
If user input is disconnect or they shutdown the terminal, then the disconnect functionality will be triggered

3.List<String> listFiles(UserToken token)
User can list all files that he or she can accessed by providing token through terminal

4.boolean upload(String sourceFile, String destFile, String group, UserToken token)
User can upload file to share with people in same group by providing sourcefile, destfile, group name and token through terminal

5.boolean download(String sourceFile, String destFile, UserToken token)
User can download files that belong to the group he or she is in by providing sourcefile, destfile and token through terminal

6.boolean delete(String filename, UserToken token)
User can delete the file that belong to the group he or she is in by providing file name and token through terminal
