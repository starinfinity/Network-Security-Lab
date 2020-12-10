package nets;

import java.io.*;
import java.math.*;
import java.security.*;

class DiffieHellmanExchange {
    int keysize;
    DHKey key;
    BigInteger x, x_pub, s_secret;

    public DiffieHellmanExchange () {  this.keysize = 512;  }

    
    public BigInteger getDHParmMakePublicKey (String filename) throws Exception {
        // get p&g from file
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream oin = new ObjectInputStream(fis);
        key = (DHKey)oin.readObject();
        oin.close();
        //generate a secure random number
        SecureRandom sr = new SecureRandom();  
        //create a secure secret key using secure random number
        x = new BigInteger(keysize, sr);       
        //create public key using p,g and secure secret key
        x_pub = key.g.modPow(x, key.p);       
        return x_pub;
    }
    
    // Build the secret for karn encryption
    public BigInteger getSecret (String s_key) {
        BigInteger pkey = new BigInteger(s_key, 32);
        s_secret = pkey.modPow(x, key.p);
        return s_secret;
    }
}