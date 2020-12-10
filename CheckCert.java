/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nets;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author gahlotrl
 */

// Shows how to verify a public key against a certificate by verifying the
// Monitor's own certificate
// The Monitor is an identity certification Authority, which stores SHA-1 hash signed with the monitor;s
// RSA private key. certificates certify public keys to enable authentication when transfering point. 
// Certificate is used by a participant to verify other participant to transfer points.
public class CheckCert {
    // The Monitor's public key is given by the following two lines
    private byte H[];
    private byte C[];
   
    BigInteger v;
    BigInteger n;
    
    //verifier takes prover's certificate using GET_CERTIFICATE command and raise it to power e(65537)
	//use the result times modulo n to get C which will be used to verify prover. 
    BigInteger mon_exp = new BigInteger("65537");
    
    BigInteger mon_mod;
    BigInteger cert;
   
   CheckCert(String pubKey)
   {
       this.mon_mod= new BigInteger(pubKey,32);
   }
   
    
 private void createC(String cert)
         
 {   this.cert=new BigInteger(cert,32);
     C= this.cert.modPow(mon_exp, mon_mod).toByteArray();
   
    
     
 }   
	//the numbers v and n are prover's public key and shared with verifier.
	//verifier creates message digest and update with both numbers shared i.e. v and n called H.
 private void createH(String v, String n){
     this.v= new BigInteger(v);
     this.n=new BigInteger(n,32);
     
     try{
                     MessageDigest md = MessageDigest.getInstance("SHA-1");
                     md.reset();
                     md.update(this.v.toByteArray());
                     md.update(this.n.toByteArray());
                     H=md.digest();
                                          

     }  catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CheckCert.class.getName()).log(Level.SEVERE, null, ex);
        }
 }
 //H calculated is now compared with C and if it matches the prover is authentic.
     public boolean checkTheCerts(String v, String n, String cert)
    {
        createC(cert);
        createH(v, n);
        
        for( int i =0,j=1; i<H.length; i++,j++)
        { 
            if(H[i]!=C[j])
            { 
                return false;
            }
        
    }
   
        return true;
 }
 
 
}
