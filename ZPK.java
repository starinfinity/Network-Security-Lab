package nets;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author gahlotrl
 * 
 * 
 * 
*/
//ZKP is used for identifing other participant to make transfer
public class ZPK extends MessageParser {

    public BigInteger sqr = new BigInteger("2", 10);

    BigInteger v;
    BigInteger n;
    BigInteger s;

    //
    ArrayList<BigInteger> subset_K;
    ArrayList<BigInteger> subset_J;

    RSAPublicKeySpec x;

    ArrayList<Integer> subset_A;
    ArrayList<Integer> not_subset_A;

    
    public BigInteger[] R;

    int rounds;
    public int[] A;
    boolean check;
    BigInteger[] RR;

    KeyPair kpKeyPair;
    KeyFactory kf;
    KeyPairGenerator kpg;

    ArrayList<BigInteger> randomR;
    ArrayList<BigInteger> randomRSquare;

	//public ZKP (int numRounds) {}
	
	//a secret s and modulus n are chosen before any transfer
	//public key v is computed which is  s*s mod n
    
    public ZPK() {
        try {
            // Generate a 512-bit RSA key pair
            kf = KeyFactory.getInstance("RSA");
            kpg = KeyPairGenerator.getInstance("RSA");

            kpg.initialize(512);
            kpKeyPair = kpg.genKeyPair();
            x = kf.getKeySpec(kpKeyPair.getPublic(), RSAPublicKeySpec.class);
        }
        catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ZPK.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (InvalidKeySpecException ex) {
            Logger.getLogger(ZPK.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    

    public ZPK(String V, String N, String S) {
     super();
     
        try {
            kf = KeyFactory.getInstance("RSA");
            kpg = KeyPairGenerator.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ZPK.class.getName()).log(Level.SEVERE, null, ex);
        }

    kpg.initialize(512);

         kpKeyPair 	= kpg.genKeyPair();
        this.v = new BigInteger(V);
        this.s = new BigInteger(S);
        this.n = new BigInteger(N);

    }

    private void generateVNS() {

        n = x.getModulus();
        s = new BigInteger(512, new SecureRandom());
        v = s.pow(2).mod(n);

    }

    public void storekeys(String path) {
        generateVNS();
        PrintWriter keyFile = null;
    e

        try {
            keyFile = new PrintWriter(new FileWriter(path));

            keyFile.println(v.toString(32) + " " + n.toString(32) + " " + s.toString(32));

        }
        catch (IOException ex) {
            Logger.getLogger(ZPK.class.getName()).log(Level.SEVERE, null, ex);
        }
        finally {
            keyFile.close();
        }

    }

    public void setPublicKey(String V, String N) {

        this.v = new BigInteger(V.trim());

        this.n = new BigInteger(N.trim());
        ;
    }

    public int setRounds(String msg) {
        StringTokenizer t = new StringTokenizer(msg, " ");

        rounds = Integer.parseInt(t.nextToken());
        return rounds;
    }
	
    public void getRounds(String msg) {
        msg = GetNextCommand(msg, "ROUNDS");
        if (msg != null) {
            int intRounds = Integer.parseInt(msg.trim());
            rounds = intRounds;
        }
    }

   
		//sends sublist of array indices A to initiator as Subset[A] 		
		public void setSubsetA(String msg) {
        subset_A = new ArrayList<Integer>();
        
        String subA = GetNextCommand(msg, "SUBSET_A");
        for (int i = 0; i < rounds; i++) {
          

            if (subA == null || subA.equals("REQUIRE") || subA.equals("<enc>")) {
                break;
            }

         
            subset_A.add(Integer.parseInt(subA.trim()));
            subA = GetNextCommand(msg, subA);
        }
    }

            
    public String getSubsetA() {
        String msg = "";
        not_subset_A= new ArrayList<>();
        subset_A = new ArrayList<>();
        for (int i = 0; i < rounds; i += 2) {
           
            
            msg += i + " ";
            subset_A.add(i);
        }
        
         for (int i = 0; i < rounds; i ++) {
            
             if(subset_A.contains(i))
                 continue;
             not_subset_A.add(i);
         
        }
        
        
        
        return msg;

    }

	//from the round, monitor chooses random numbers  R[0]....R[6] and passes square of those number times mod n
	//example R[0]^2*mod n
	// that set of numbers is known as AUTHORIZE_SET 
    public String getAuthorizeSet() {
        Random rnd = new Random();
        randomR = new ArrayList<BigInteger>();
        randomRSquare = new ArrayList<BigInteger>();
        String msg = "";
        for (int i = 0; i < rounds; i++) {
            randomR.add(new BigInteger(256, rnd));

            
            randomRSquare.add(randomR.get(i).modPow(sqr, n));
            msg += " " + randomRSquare.get(i).toString();
        }
        return msg;
    }

    public void setAuthorizeSet(String msg) {
        String thisAuthNum = GetNextCommand(msg, "AUTHORIZE_SET");

        randomRSquare = new ArrayList<BigInteger>();
        for (int i = 0; i < rounds; i++) {

            if (thisAuthNum == null || thisAuthNum.equals("REQUIRE") || thisAuthNum.equals("<enc>")) {
                break;
            }

            randomRSquare.add(new BigInteger(thisAuthNum.trim()));
            thisAuthNum = GetNextCommand(msg, thisAuthNum);
        }

    }

    public void saveRounds(String msg) {
        StringTokenizer t = new StringTokenizer(msg, " ");
        t.nextToken();
        rounds = Integer.parseInt(t.nextToken());
    }

    public String getSubsetK() {
        String msg = "";
        subset_K = new ArrayList<BigInteger>();
        for (int i = 0; i < subset_A.size(); i++) {
            
            
            subset_K.add(randomR.get(subset_A.get(i)).multiply(s).mod(n));
            msg += subset_K.get(i) + " ";
        }
        return msg;
    }
	
	//initiator recieves SUBSET A and computes SUBSET K where K[i]=s*R[A[i]]
    public void setSubsetK(String msg) {
        subset_K = new ArrayList<BigInteger>();
        String subk = GetNextCommand(msg, "SUBSET_K");
        for (int i = 0; i < rounds; i++) {

            if (subk == null || subk.equals("REQUIRE") || subk.equals("RESULT") || subk.equals("<enc>")) {
                break;
            }

            
            subset_K.add(new BigInteger(subk.trim()));
            subk = GetNextCommand(msg, subk);

        }
    }

    public boolean checkSubsetK() {
        check = true;

        for (int i = 0; i < subset_K.size(); i++) {
            BigInteger a1 = subset_K.get(i).modPow(sqr, n);
            BigInteger a2 = v.multiply(randomRSquare.get(subset_A.get(i))).mod(n);
            if (!a1.equals(a2)) {
                check = false;
                return false;
            }
        }
        return true;
    }
	
	// initiator generates SUBSET J which operates on all indices of R not in SUBSET A
    public String getSubsetJ() {
        int j = 0;
        subset_J = new ArrayList<BigInteger>();
        String msg = "";
        for (int i = 0; i < rounds; i++) {
            if (!checkIn_subA(i)) {
                subset_J.add(randomR.get(i).mod(n));
                msg += " " + subset_J.get(j++);

            }

        }
        return msg;
    }

    public boolean checkIn_subA(int idx) {
        for (int j = 0; j < subset_A.size(); j++) {
            if (idx == subset_A.get(j)) {
                return true;
            }
        }
        return false;
    }

    public void setSubsetJ(String msg) {
        subset_J = new ArrayList<BigInteger>();
        String subj = GetNextCommand(msg, "SUBSET_J");
        for (int i = 0; i < rounds; i++) {

            if (subj == null || subj.equals("REQUIRE") || subj.equals("RESULT") || subj.equals("<enc>")) {
                break;
            }
            subset_J.add(new BigInteger(subj.trim()));
            subj = GetNextCommand(msg, subj);

        }
    }

    public boolean checkSubsetJ() {
       

        for (int i = 0; i < subset_J.size(); i++) {
            BigInteger a1 = subset_J.get(i).modPow(sqr, n);
            System.out.println("checkj"+a1);
            BigInteger a2 = randomRSquare.get(not_subset_A.get(i));
            System.out.println("cehckj"+a2);
            if (!a1.equals(a2)) {
               
                return false;
            }
        }
        return true;
    }
            

    public String response() {
        if (checkSubsetJ() && checkSubsetK()) {
            return "ACCEPT";
        }
        else {
            return "DECLINE";
        }

    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getS() {
        return s;
    }

    public BigInteger getV() {
        return v;
    }
	
	//write keys to file
    public void writeKeys(String path) {
        try {
            PrintWriter file = new PrintWriter(new FileWriter(path));

            generateVNS();
            file.println(v.toString(32) + " " + n.toString(32) + " " + s.toString(32));

            file.close();
        }
        catch (IOException e) {
            System.out.println("ZPK I/O exception: " + e);
        }
        catch (NullPointerException e) {
            System.out.println("ZPK Null Pointer: " + e);
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }

 /* 
 * @param arg 
 */
    public static void main(String[] arg) {

//        String[] args = {"SPARE_ONE-1", "SPARE_ONE-2", "SPARE_ONE-3"};
//        ZPK zpk = new ZPK();
//        for (String s : args) {
//
//            zpk.writeKeys("users/keys/" + s + "_pubkey.dat"
//            );
//
//        }
//        
         String args[]={
            "7356307484142255475720469456186878629084331071291633048691772773100553038498994311154127375922909692609087814365063854861304539393130371863066551513071111",
"11041630550614797812463801807549896073902219097070380128449081248397030711698428017292985444473324373497174591017554073217898904651507617231052607139097861"
,"12660423810729395213862188775125987286506647114939953790403678476332352310186450782850632180424613595966868874893385151677177541679077360288486551888051795"};



    
            
        ZPK fish = new ZPK(args[0],
		
                        
                        args[1],
										 args[2]);
                
                //V 
                
                // N
                
                //S
                
                
		fish.rounds=4;
		String RR 		= fish.getAuthorizeSet();
		String A 		= fish.getSubsetA();
		String K 		= fish.getSubsetK();
		String J 		= fish.getSubsetJ();
                
                System.out.println(J);

		System.out.println("test:");
		//System.out.println(rounds);
		System.out.println(RR);
		System.out.println(A);
		System.out.println(K);
		System.out.println(J);
		
		System.out.println(fish.response());
	}    
            
            
            
            
            
            
            
            
            }


