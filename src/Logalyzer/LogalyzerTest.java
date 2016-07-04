package Logalyzer;

import org.junit.Test;
import static org.junit.Assert.*;
import Logalyzer.LogException;

/**
 * Created by ReaperMan on 7/1/2016.
 */
public class LogalyzerTest {

    private String path = "C:\\rorydev\\mm_workspace\\Logalyzer\\out\\artifacts\\BBIVRLogalyzer_jar\\";
    private String pattern = "59BF2C55C1440A8FEEEBB1338D9D6064:/bbIVR";
    private String commandPath = "C:\\cygwin64\\bin\\grep.exe";

    @Test
    public void testSearchPattern(){

        Logalyzer log = new Logalyzer(path, commandPath);

        try{
            System.out.println("Running Test...");
            System.out.println("Output from run method" + log.searchJavaSession(pattern).toString());
        }
        catch(LogException e){
            System.out.println("Error: " + e.getMessage());
        }
    }

    @Test
    public void testGetSessionIds(){
        Logalyzer log = new Logalyzer(path, commandPath);
        try{
            System.out.println("Running testGetSessionIds Test...");
            System.out.println("Output from run method:" +System.lineSeparator()+ log.getSessionIdsFromLog(path));
        }
        catch(LogException e){
            System.out.println("Error: " + e.getMessage());
        }

    }

    @Test
    public void testGetSSH(){
        try{
            Logalyzer log = new Logalyzer();
            log.setLogPath(System.getProperty("user.dir"));
            log.sftpFromServer("/home/reaperman/logs/rh.rdctech.com/http", "reaperman", "rh.rdctech.com","13371337");
        }
        catch(LogException e){
            System.out.println("Error in test: " + e.getMessage());
        }
    }
}
