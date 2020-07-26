import java.util.*;
import java.io.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import java.io.*;
import javax.crypto.spec.IvParameterSpec;
import java.lang.*;
public class Token implements UserToken, Serializable
{
    public String Issuer;
    public String Subject;
    public ArrayList<String> Groups;
    private byte[] signature = null;
    private String digitalMSG; // test signature with this message
    
    
    
    public Token(String Issuer, String Subject)
    {
        this.Issuer = Issuer;
        this.Subject = Subject;
        this.Groups = new ArrayList<String>();
    }
    public Token(String Issuer, String Subject, ArrayList<String> Groups)
    {
        this.Issuer = Issuer;
        this.Subject = Subject;
        this.Groups = new ArrayList<String>(Groups.size());
        for(int i=0; i<Groups.size(); i++)
        {
            this.Groups.add(Groups.get(i));
        }
    }
    
    public Token(String Issuer, String Subject, ArrayList<String> Groups, byte[] signature, String digitalMSG)
    {
        this.Issuer = Issuer;
        this.Subject = Subject;
        this.Groups = new ArrayList<String>(Groups.size());
        this.signature = signature;
        // each signature correspond to one user
        // signature proves this token has at least been assigned by group server
        this.digitalMSG = digitalMSG;
        
        for(int i=0; i<Groups.size(); i++)
        {
            this.Groups.add(Groups.get(i));
        }
    }
    
    public String getIssuer()
    {
        return this.Issuer;
    }
    
    public String getSubject()
    {
        return this.Subject;
    }
    
    public ArrayList<String> getGroups()
    {
        return this.Groups;
    }
    
    public byte[] getSignature()
    {
        return this.signature;
    }

    public void setSignature(byte[] sig) {
        signature = sig;
    }

    public String getContents() {
        StringBuilder contents = new StringBuilder(Issuer);
        contents.append(Subject);
        for (int i = 0; i < Groups.size(); i++) {
            contents.append(Groups.get(i));
        }
        return contents.toString();
    }
    
    public String getMSG()
    {
        return this.digitalMSG;
    }
    
    public void addGroups(String groupname)
    {
        this.Groups.add(groupname);
    }
    
    public void deleteGroups(String groupname)
    {
        if(!this.Groups.isEmpty())
        {
            if(this.Groups.contains(groupname))
            {
                this.Groups.remove(this.Groups.indexOf(groupname));
            }
        }
    }


}
