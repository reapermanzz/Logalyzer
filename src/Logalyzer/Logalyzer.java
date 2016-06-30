package Logalyzer;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Created by rhenderson on 6/28/2016.
 */
public class Logalyzer {

    private String logPath;

    public static void main(String args[]){
        if(args.length == 0){
            GUI graphicalInterface = new GUI("BlackBerry IVR Log Analyzer", 1024, 768);
            try{
                //graphicalInterface.getDisplayConsole().append(searchJavaSession("59BF2C55C1440A8FEEEBB1538D9D6064:/bbIVR").toString());
                System.out.println("Running command");
                System.out.println("output: " + searchJavaSession("59BF2C55C1440A8FEEEBB1538D9D6064:/bbIVR").toString());
            }
            catch(LogException e){
                System.out.println("Error: " + e.getMessage());
            }
        }
        else{
            return;
        }

    }

    private static StringBuilder searchJavaSession(String sessionId)throws LogException{
        try{
            StringBuilder output = new StringBuilder();
            String line;
            Process p = Runtime.getRuntime().exec("c:\\cygwin64\\bin\\grep.exe " + "-e \"sessionId\"" + " \"c:\\rorydev\\telephony\\log traces\\goodcalls\\firstCall.txt");
            BufferedReader bri = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while((line = bri.readLine()) != null){
                output.append(line);
            }
            bri.close();

            /*if(output == null)
            {
                BufferedReader bre = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                while((line = bre.readLine()) != null){
                    output.append(line);
                }
                bre.close();
            }*/

            p.waitFor();
            return output;
        }
        catch(Exception e){
            throw new LogException("Error occurred: " + e.getMessage());
        }


    }
}
