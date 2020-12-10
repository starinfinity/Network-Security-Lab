/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author macbookpro
 */
public class KeyManager {
   
    private String getV;
    private String getN;
    private String getS;
    
    
    KeyManager(String Ident) 
    {
      try {
           
            BufferedReader br = new BufferedReader( new FileReader(new File("users/keys/"+Ident+"_pubkey.dat")));
            
            parseFile(br.readLine());
            
            
         
        } catch (FileNotFoundException ex) {
            System.out.println("File Missing ");
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        } 
        
    }  
        
   private void parseFile(String input)
           
   {
       String values[]=input.split(" ");
       getV=values[0].trim();
       getN=values[1].trim();
       getS= values[2].trim();
       


}

  

    public String getGetV() {
        return getV;
    }

    public String getGetN() {
        return getN;
    }

    public String getGetS() {
        return getS;
    }
    
}
