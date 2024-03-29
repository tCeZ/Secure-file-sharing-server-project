/* This list represents the users on the server */
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.lang.*;



	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
        
		
		public synchronized void addUser(String username)
		{
			User newUser = new User();
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		public synchronized void setUserHash(String username, byte[] passHash) {
			list.get(username).setHash(passHash);
		}
		
		public synchronized byte[] getUserHash(String username) {
			return list.get(username).getHash();
		}
		
		public synchronized Enumeration<String> getUsernames()
		{
			return list.keys();
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
        
        public synchronized ArrayList<String> getAllUsers()
        {
            ArrayList<String> allUsers = new ArrayList<String>(list.keySet());
            return allUsers;
             
        }
        
        public synchronized void setKey(String user, KeyPair key)
        {
            list.get(user).setKey(key);
        }
        
        public synchronized KeyPair getKeyPair(String username)
        {
            return list.get(username).key;
        }
        
        public synchronized boolean verification(String user, String msg, byte[] signature)
        {
            boolean verificate;
            try
            {
                Signature publicSignature = Signature.getInstance("SHA256withRSA");
                publicSignature.initVerify(list.get(user).key.getPublic());
                publicSignature.update(msg.getBytes());
                verificate = publicSignature.verify(signature);
            }
            catch(Exception e)
            {
                return false;
            }
            return verificate;
        }
        
        public synchronized void setToken(String user, UserToken token)
        {
            list.get(user).setToken(token);
        }
        
        public synchronized UserToken getToken(String user)
        {
            return list.get(user).token;
        }
        
		
	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
        //private byte[] plainText;
        private KeyPair key;
        private UserToken token;
        private byte pwHash[];
		
		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
            //plainText = null;
            key = null;
		}
        
        public void setKey(KeyPair key)
        {
            this.key = key;
        }

        public void setHash(byte newHash[]) {
			pwHash = newHash;
		}
		
		public byte[] getHash() {
			return pwHash;
		}
        
        /*public void setPlainText(byte[] plainText)
        {
            this.plainText = plainText;
        }*/
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
        
        public void setToken(UserToken token)
        {
            this.token = token;
        }
		
	}
	
}	
