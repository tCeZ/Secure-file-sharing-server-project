import java.util.*;
import java.io.*;
public class Token implements UserToken, Serializable
{
    public String Issuer;
    public String Subject;
    public ArrayList<String> Groups;
    
    
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
    
    public String getIssuer()
    {
        return this.Issuer;
    }
    
    public String getSubject()
    {
        return this.Subject;
    }
    
    public List<String>getGroups()
    {
        return this.Groups;
    }


}
