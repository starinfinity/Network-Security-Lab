package homework;

import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;
import java.awt.*;


public class ActiveClient extends MessageParser implements Runnable {

   public static String MonitorName;
   Thread runner;
   Socket toMonitor = null;
   public static int MONITOR_PORT;
   public static int LOCAL_PORT;
   public int SleepMode;
   int DELAY = 90000;  //Interval after which a new Active Client is started 
   long prevTime,present;

   public ActiveClient() {
      super("[no-name]", "[no-password]");
      MonitorName="";
      toMonitor = null;
      MONITOR_PORT=0;
      LOCAL_PORT=0;
   }
             
   public ActiveClient(String mname, int p, int lp, int sm, 
                       String name, String password) {
      super(name, password);
      try {
         SleepMode = sm;
         MonitorName = mname; 
         MONITOR_PORT = p; 
         LOCAL_PORT = lp;
      } catch (NullPointerException n) {
         System.out.println("Active Client [Constructor]: TIMEOUT Error: "+n);
      }
   }

   public void start() {
      if (runner == null) {
         runner = new Thread(this);
         runner.start();
      }
   }  

   public void run() {
      while(Thread.currentThread() == runner) { 
         try {                         
	    System.out.print("Active Client: trying monitor: "+MonitorName+
                               " port: "+MONITOR_PORT+"...");
            toMonitor = new Socket(MonitorName, MONITOR_PORT);
	    System.out.println("completed.");
            out = new PrintWriter(toMonitor.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(toMonitor.getInputStream()));

            HOSTNAME = toMonitor.getLocalAddress().getHostName();
            CType = 0;   //Indicates Client 
            HOST_PORT = LOCAL_PORT;
            if (!Login()) {
               if (IsVerified == 0) System.exit(1);
            }
	    System.out.println("***************************");
	    if (Execute("GET_GAME_IDENTS")) {
	       String msg = GetMonitorMessage();
	       System.out.println("ActiveClient [GET_GAME_IDENTS]:\n\t"+msg);
	    }
	    if (Execute("RANDOM_PARTICIPANT_HOST_PORT")) {
	       String msg = GetMonitorMessage();
	       System.out.println("ActiveClient [RANDOM_PARTICIPANT_HOST_PORT]:\n\t"+msg);
	    }
	    if (Execute("PARTICIPANT_HOST_PORT", "FRANCO")) {
	       String msg = GetMonitorMessage();
	       System.out.println("ActiveClient [PARTICIPANT_HOST_PORT]:\n\t"+msg);
	    }
	    if (Execute("PARTICIPANT_STATUS")) {
	       String msg = GetMonitorMessage();
	       System.out.println("ActiveClient [PARTICIPANT_STATUS]:\n\t"+msg);
	    }
	    ChangePassword(PASSWORD);
	    System.out.println("Password:"+PASSWORD);

            toMonitor.close(); 
            out.close(); 
            in.close();
            try { runner.sleep(DELAY); } catch (Exception e) {}
                            
         } catch (UnknownHostException e) {
         } catch (IOException e) {
            try { 
               toMonitor.close();  
               //toMonitor = new Socket(MonitorName,MONITOR_PORT);
            } catch (IOException ioe) {
            } catch (NullPointerException n) { 
               try {
                  toMonitor.close();  
                  //toMonitor = new Socket(MonitorName,MONITOR_PORT);
               } catch (IOException ioe) {}
            }
         }
      }
   }

   private void setIdentification(String rawMonitorResponse) throws IOException{
	      String iddir = IDENT+".dat";
	      File identFile = new File(iddir);
	      if (!identExists(identFile)){
	         System.out.println("File creation error");
	         System.exit(1);
	      }
	      String password = "PASSWORD abcdef12 ";
	      //Scanner obj= new Scanner(System.in);
	   	  //System.out.println("Password required");
	   	  //password = obj.nextLine();
		  //obj.close();
	      try {
	    	  BufferedWriter out= new BufferedWriter(new FileWriter(iddir));
	    	  out.write(IDENT+" "+password);
	    	  out.close();
		} catch (IOException e) {
			System.out.println("file writing exceptions");
			System.exit(1);
		}
	      
	   }

	   private boolean identExists(File file) throws IOException{
	      return (file.exists()) ? file.exists() : file.createNewFile();
	   }

	   public boolean Login() { 
	      boolean success = false; 
	      
	      String monitormessage = ""; 
	      String[] credentials = new String[]{"IDENT", "PASSWORD", "HOST_PORT"};
	      int i = 0;
	      try { 
	         for(String s : credentials){
	            if(Execute(s)){
	            	monitormessage = GetMonitorMessage();
	               System.out.println(monitormessage);
	               try{
	                  if(i == 1) setIdentification(monitormessage);
	               }catch(IOException e){
	                  System.out.println("set identification error "+e);
	                  System.exit(1);
	               }
	               if(i++ == (credentials.length-1)) success = true;
	            }
	         }         
	      } catch (NullPointerException n) {
	          System.out.println("MessageParser [Login]: null pointer error "+
	  			    "at login:\n\t"+n);
	           success = false;
	      }
	           System.out.println("Success Value Login = "+success);
	      return success;
	   }
	}
