/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;
	private final PrivateKey fsPrivKey;
	private final PublicKey gsKey;
	private Key sessionKey;
    
    
    

	public FileThread(Socket _socket, FileServer _fs, PrivateKey _fsPrivKey, PublicKey _gsKey)
	{
		socket = _socket;
    	my_fs = _fs;
		fsPrivKey = _fsPrivKey;
		gsKey = _gsKey;
	}

	public void run()
	{
		boolean proceed = true;
    	Security.addProvider(new BouncyCastleProvider());

		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope env = (Envelope)input.readObject();
				System.out.println("Request received: " + env.getMessage());

				// First parse through publicly accessible messages
				if (env.getMessage().equals("GETPUBKEY")) { // Client wants the public key
					response = new Envelope("OK");
					response.addObject(my_fs.getServerPublicKey());
					output.writeObject(response);
				}
				else if (env.getMessage().equals("KCF")) { // Client wants a session key
					// Decrypt sealed object with private key
					SealedObject sealedObject = (SealedObject)env.getObjContents().get(0);
					String algo = sealedObject.getAlgorithm();
					Cipher cipher = Cipher.getInstance(algo);
					cipher.init(Cipher.DECRYPT_MODE, fsPrivKey);
					// Get KeyPack challenge/key combo from sealedObject
					KeyPack kcf = (KeyPack)sealedObject.getObject(cipher);
					int challenge = kcf.getChallenge();
					sessionKey = kcf.getSecretKey();
					// Get IV from message
					byte IVarray[] = (byte[])env.getObjContents().get(1);
					
					// Encryption of challenge response
					Cipher theCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					challenge += 1;
					byte plaintext[] = new byte[4];
					plaintext[0] = (byte)(challenge >> 24);
					plaintext[1] = (byte)(challenge >> 16);
					plaintext[2] = (byte)(challenge >> 8);
					plaintext[3] = (byte)(challenge /*>> 0*/);
					theCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
					byte[] cipherText = theCipher.doFinal(plaintext);
					
					// Respond to the client
					response = new Envelope("OK");
					response.addObject(cipherText);
					output.writeObject(response);
				}
				
				else if (env.getMessage().equals("ENV")) { // encrypted Envelope
					// decrypt contents of encrypted Envelope and pass to branches below
					Envelope e = decryptEnv(env);
					System.out.println("ENV: " + e.getMessage());
				
					if (e.getMessage().equals("LGROUPS")) {
						if (e.getObjContents().size() < 1) {
							response = new Envelope("FAIL-BADCONTENTS");
						}
						else {
							if (e.getObjContents().get(0) == null) {
								response = new Envelope("FAIL-BADTOKEN");
							}
							else {
								Token yourToken = (Token)e.getObjContents().get(0); //Extract token
								if (authToken(yourToken)) {
									List<String> groupList = yourToken.getGroups(); // get groups
									response = new Envelope("OK"); //Success
									response.addObject(groupList);
								}
								else {
									response = new Envelope("FAIL-BADTOKENAUTH");
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}
					else if (e.getMessage().equals("CGROUP")) {
						if (e.getObjContents().size() < 2) {
							response = new Envelope("FAIL-BADCONTENTS");
						}
						else {
							if (e.getObjContents().get(0) == null) {
								response = new Envelope("FAIL-BADGROUP");
							}
							if (e.getObjContents().get(1) == null) {
								response = new Envelope("FAIL-BADTOKEN");
							}
							else {
								String changeGroup = (String)e.getObjContents().get(0); //Extract group
								Token yourToken = (Token)e.getObjContents().get(1); //Extract token
								if (authToken(yourToken)) {
									// check that it is a valid group
									if (yourToken.getGroups().contains(changeGroup)) {
										response = new Envelope("OK"); //Success
										List<String> changeGroupList = new ArrayList<String>();
										changeGroupList.add(changeGroup);
										
										response.addObject(changeGroupList);
									}
									else {
										response = new Envelope("FAIL-BADGROUP");
									}
								}
								else {
									response = new Envelope("FAIL-BADTOKENAUTH");
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}


					// Handler to list files that this user is allowed to see
					if(e.getMessage().equals("LFILES"))
					{ 
		                
		               
					    if(e.getObjContents().size() < 1)
						{
							response = new Envelope("FAIL-BADCONTENTS");
						}
						else
						{
							if(e.getObjContents().get(0) == null) {
								response = new Envelope("FAIL-BADTOKEN");
							}
							else
							{
		                        response = new Envelope("FAIL-BADTOKEN");
								// extracting the user token
								UserToken yourToken = (UserToken)e.getObjContents().get(0); 
		                        // extracting userlist for authentication
		                        UserList ul = (UserList)e.getObjContents().get(1);
								String username = yourToken.getSubject();
		                        boolean checkToken = checkTokenValid(yourToken,ul);
								String outputStr;
								List<ShareFile> fullFileList = FileServer.fileList.getFiles();
								List<String> userFileList = new ArrayList<String>();
								if (fullFileList != null)
								{
									for (ShareFile sf: fullFileList)
									{
										if (yourToken.getGroups().contains(sf.getGroup()))
										{
											userFileList.add(sf.getPath() + "\t(" + sf.getOwner() + "/" + sf.getGroup() + ")");
										}
									}
								}
		                        
		                        if(checkToken)
		                        {
		                            response = new Envelope("OK"); //Success
		                            response.addObject(userFileList);
		                        
		                        }
		                       

								
							}
						}
						output.writeObject(response);
					}
					if(e.getMessage().equals("UPLOADF"))
					{

						if(e.getObjContents().size() < 3)
						{
							response = new Envelope("FAIL-BADCONTENTS");
						}
						else
						{
							if(e.getObjContents().get(0) == null) {
								response = new Envelope("FAIL-BADPATH");
							}
							if(e.getObjContents().get(1) == null) {
								response = new Envelope("FAIL-BADGROUP");
							}
							if(e.getObjContents().get(2) == null) {
								response = new Envelope("FAIL-BADTOKEN");
							}
		                    if(e.getObjContents().get(3) == null) {
								response = new Envelope("FAIL-BADAUTHENTICATION");
							}
							else {
								String remotePath = (String)e.getObjContents().get(0);
								String group = (String)e.getObjContents().get(1);
								UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
		                        UserList ul = (UserList)e.getObjContents().get(3);
		                        
		                         boolean checkToken = checkTokenValid(yourToken,ul);
		                        // check whether this token is real
		                        

								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS"); //Success
								}
		                        else if(!checkToken)
		                        {
		                            System.out.printf("Check your token!");
		                            response = new Envelope("FAIL_FORGEDTOKEN");
		                            


		                        }
								else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED"); //Success
								}
								else  {
									File file = new File("shared_files/"+remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									response = new Envelope("READY"); //Success
									output.writeObject(response);

									e = (Envelope)input.readObject();
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										output.writeObject(response);
										e = (Envelope)input.readObject();
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
										response = new Envelope("OK"); //Success
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
							}
						}

						output.writeObject(response);
					}
					else if (e.getMessage().compareTo("DOWNLOADF")==0) {

						String remotePath = (String)e.getObjContents().get(0);
						Token t = (Token)e.getObjContents().get(1);
		                UserList ul = (UserList)e.getObjContents().get(2);
		                boolean checkToken = checkTokenValid(t,ul);
		                // check whether this token is real
		                if(!checkToken)
		                {
		                    System.out.printf("Check your token!");
		                    e = new Envelope("ERROR_TOKEN");
							output.writeObject(e);
		                    
		                
		                }
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING");
							output.writeObject(e);

						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							output.writeObject(e);
						}
						else {

							try
							{
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								output.writeObject(e);

							}
							else {
								FileInputStream fis = new FileInputStream(f);

								do {
									byte[] buf = new byte[4096];
									if (e.getMessage().compareTo("DOWNLOADF")!=0) {
										System.out.printf("Server error: %s\n", e.getMessage());
										break;
									}
									e = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) {
										System.out.printf(".");
									} else if (n < 0) {
										System.out.println("Read error");

									}


									e.addObject(buf);
									e.addObject(new Integer(n));

									output.writeObject(e);

									e = (Envelope)input.readObject();


								}
								while (fis.available()>0);

								//If server indicates success, return the member list
								if(e.getMessage().compareTo("DOWNLOADF")==0)
								{

									e = new Envelope("EOF");
									output.writeObject(e);

									e = (Envelope)input.readObject();
									if(e.getMessage().compareTo("OK")==0) {
										System.out.printf("File data upload successful\n");
									}
									else {

										System.out.printf("Upload failed: %s\n", e.getMessage());

									}

								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}
							}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);

							}
						}
					}
					else if (e.getMessage().compareTo("DELETEF")==0) {

						String remotePath = (String)e.getObjContents().get(0);
						Token t = (Token)e.getObjContents().get(1);
		                UserList ul = (UserList) e.getObjContents().get(2);
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
		                boolean checkToken = checkTokenValid(t,ul);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
		                else if(!checkToken)
		                {
		                    System.out.printf("Check your token!");
		                    e = new Envelope("ERROR_TOKEN");
		                    output.writeObject(e);


		                }
						else {

							try
							{


								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
								}


							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
							}
						}
						output.writeObject(e);
					}
				}

				else if(env.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
    
    private boolean checkTokenValid(UserToken yourToken, UserList ul)
    {
        
        if(!ul.verification(yourToken.getSubject(),  yourToken.getMSG(), yourToken.getSignature()))  // check signature, whether this token is totally created by user
        {                                                                                                       // without consideration to modification by user at this step.
            return false;
        }
        
        UserToken db_Token = ul.getToken(yourToken.getSubject()); // Valid token information saved in group server
        
        if(!yourToken.getSubject().equals(db_Token.getSubject()) || !yourToken.getIssuer().equals(db_Token.getIssuer()))
        {
            return false;
        }
        
        ArrayList<String> YourGroups = yourToken.getGroups();
        ArrayList<String> db_Groups = db_Token.getGroups();
        
        if(YourGroups.size() != db_Groups.size()) // not same access right to groups
        {
            return false;
        }
        
        for(int i=0; i<YourGroups.size(); i++) // token provided by user include access right to different group
        {
            if(!db_Groups.contains(YourGroups.get(i)))
            {
                return false;
            }
        }
        
        return true;
        
        
    }

    private Envelope decryptEnv(Envelope msg) {
		// Remove objects of envelope
		SealedObject so = (SealedObject)msg.getObjContents().get(0);
		byte[] IVarray = (byte[])msg.getObjContents().get(1);
		try {
			String algo = so.getAlgorithm();
			Cipher envCipher = Cipher.getInstance(algo);
			envCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
			return (Envelope)so.getObject(envCipher); // return decrypted envelope
		}
		catch (Exception e) {
			System.out.println("Error: " + e);
			e.printStackTrace();
		}
		return null;
	}
	
	private Envelope encryptEnv(Envelope msg) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			SecureRandom IV = new SecureRandom();
			byte IVarray[] = new byte[16];
			IV.nextBytes(IVarray);
			cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
			SealedObject so = new SealedObject(msg, cipher);
			Envelope encryptedMsg = new Envelope("ENV");
			encryptedMsg.addObject(so);
			encryptedMsg.addObject(IVarray);
			return encryptedMsg;
		}
		catch (Exception e) {
			System.out.println("Error: " + e);
			e.printStackTrace();
		}
		return null;
	}

	public boolean authToken(Token aToken) {
		try {
			// Signature verification
			Signature signed = Signature.getInstance("SHA1WithRSA", "BC");
			signed.initVerify(gsKey);
			signed.update(aToken.getContents().getBytes());
			if (signed.verify(aToken.getSignature())) {
				// RSA Signature verified
				return true;
			}
			else {
				 // RSA Signature bad
				return false;
			}
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}

}
