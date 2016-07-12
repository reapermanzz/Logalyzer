package Logalyzer;

/**
 * Created by ReaperMan on 7/1/2016.
 */
public class CLI extends Logalyzer {
    public static void main(String args[]) {
        if(args.length != 0)
        {
            if (args[0].toString().equalsIgnoreCase("gui")) {

            } else {
                return;
            }
        }
        else{
            GUI graphicalInterface = new GUI("BlackBerry IVR Log Analyzer", 1280, 1024);
        }
    }
}
