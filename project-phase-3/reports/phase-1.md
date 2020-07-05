# CS 1653 Project Phase-1

Ted (Ce) Zhang, cez17@pitt.edu, TeddyZ95\
Zhouxin Tian, zht14@pitt.edu, zht14
 

## Section 1 - Security Properties

Property 1: Limitation. Limitation states that if file f is being operated by any member of group g, then other members cannot do any actions toward the file f at the same time. Without this requirement, any user could interfere with file f while others are still working on it, which may cause data integrity issues.
 
Property 2: Authentication. Authentication states that the group server should authenticate and authorize the member of group p each time when she or he tries to access the file servers. Without this requirement, attackers may spoof any member in group p and attack file servers, which may cause great damage on file servers.

Property 3: Feasibility. Feasibility states that the group server should provide understandable authentication and authorization steps to users. Without this requirement, users may tend to circumvent the security check process, which may cause the security system to be invalid.

Property 4: Separation. Separation states that the group server should provide two keys to authenticate and authorize the users. Without this requirement, the security check tends to become more delicate and inflexible, which may increase the error probability of the security system.

Property 5: Suspicion. Suspicion states that the group server should deny access to all users by default and grant permission to users who pass the authentication and authorization. Without this requirement, attacks would be able to spoof the users who have authority by default, which may cause great damage on the file server.

Property 6: Economy. Economy states that the group server should never make assumptions about users’ behavior. Without this requirement, the security system would overlook the potential risk, which may leave open holes to attackers.

Property 7: Publicity. Publicity states the design of the file sharing system should not be secret. Without this requirement, users may not be aware of the potential dangers that they are exposed to on the internet, which may even lead to more serious consequences.

Property 8: Accessibility. Access states that if file f is shared among members of group g, then it must be accessible by members of group g when no one is working on the file. Without this requirement, users could not even access the file that they need to, which contradicts with the notion of group-based file sharing.

Property 9: Limitation-II. Limitation-II states that if one user creates/deletes a user/group, then other users cannot do any action toward that user/group at the same time. Without this requirement, any user could interfere with user data and group, which may affect the normal operation of the system.

Property 10: Stability. Stability states that if users are operating under the file sharing system, their operation should not be suspended in the middle. Without this requirement, users may encounter operation failure, which may affect the utility of users.

Property 11: Permission. Permission states that only users of the same group will be allowed specific privileges given to them by the system administrator. That includes reading, writing and execution of files. Without this requirement, users could have insufficient or total control over the file sharing server - either extremes is not ideal for the system. 

Property 12: Overwrite. Overwrite states that when a user is overwriting a file, it will only allow the overwrite only if the file is accessible to the user. Without this requirement, users could possibly overwrite files that are on other file servers that they should not have access to.

Property 13: Protection. Protection states that uploaded files to the servers will be checked for malicious content. Without this requirement users could knowingly or unknowingly be breaking/infecting the servers with malicious malware or viruses. 

Property 14: Hidden. Hidden states that other file serves should be hidden from the view of users that are not in that respective group. This will make it easier for users to grasp what directory of servers that are allocated to them. Without this property there will be possible confusion about the access rights of users. 

Property 15: Responsibility. Responsibility states that the system administrator shall have more privileges than group users. They will be able to create groups, assign users to groups with specific user privileges. Without this requirement, there would not be a way to differentiate the responsibility of user and administrator.

Property 16: Management. Management states that the file sharing system should be monitored and improved in a certain frequency. Without this requirement, the file sharing system may be uncertain and capricious, which is contrary to the original intention of the file sharing system.

## Section 2 - Threat Models

### Computer Clusters

A secure group based file sharing application is a common feature in modern storage and databases. One common example is a computer cluster or network. These are commonly found within Universities like Pitt or CMU. A group server will authenticate and manage groups that will have specific access to it through a user-specific port and a MAC address. The file sharing system will be implemented so that certain research groups can share important documents/files that they want to keep within the lab or offline. It will serve as a place of storage and obviously sharing of files. 

The trust assumptions that will be made to this system is that the users that get access to the servers are not malicious users. In addition, the user specific ports are only ones able to access the file servers. The system administrator has a log of all allowed ports that are available and each user is given a unique port. 

-  Property 2: Authentication. For this system the authentication is initialized at the creation of the user access. From there on out if the port number is a verified the system will give user access. 

-  Property 11: Permission. For this system the permission will be granted by the system administrator on what the access privileges are for users. 

-  Property 14: Hidden. For this system file servers will be hidden from other users that do not have the access right to it. 

-  Property 16: Management. For this system the file servers will be monitored for improvements like storage size. 

### Cloud Storage

Another file sharing server that many people use is cloud storage. A big provider of this service is Google with their google drive platform. In essence, it creates file servers in the “cloud” to personal users. Comparably, like many file sharing services it offers multiple users to share files within a group. 

The trust assumption for this system is that it will be online and direct authentication to the user’s own cloud container does not need authentication, but to a group’s shared files there will be a level of authorization. In addition, the group will be self-contained and the admin of the group will only have administrative privileges over the users of that group. To be added to a group a user will have a unique ID that gets added to a list of allowed members or an invitation is sent to them that initializes the same process to add a user to a specified list of allowed users. All users given access have the privileges to read, write, execute files. They will be able to 

-  Property 2: Authentication. For this system every time a user wants to access the group, the system will check if their unique ID is listed as an allowed member. 

-  Property 3: Feasibility. Since this platform is online and any user using the platform can create a group, a detailed formula is needed to allow proficient access and usage. 

-  Property 5: Suspicion. All users should be denied if they are trying to access the group’s url directly, unless they are on the allowable list. 

-  Property 7: Publicity. For this system, all groups will be viewable by the public and the implementations for all group sharing will be identical. 

-  Property 8: Accessibility. The files being shared in a group should exist on the platform’s server indefinitely. 

-  Property 13: Protection. For this system any upload or download of files from the group will automatically be checked/scanned to see if there is any malicious content since the server is online. 

-  Property 15: Responsibility. There will not be a system wide administrator for the server - there will be for the platform, however. The user that creates the group will have administrative control over what is shared in the group and who is allowed in the group. 

## Section 3 - References 

We used our brains :). So these might not be entirely comprehensive :(.



