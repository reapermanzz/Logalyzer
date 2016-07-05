package Logalyzer;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import net.sf.jftp.*;
import net.sf.jftp.net.FtpClient;
import net.sf.jftp.net.FtpConnection;
import net.sf.jftp.net.FtpTransfer;
import net.sf.jftp.system.logging.Log;

import java.io.*;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;


/**
 * Created by rhenderson on 6/28/2016.
 */
public class Logalyzer {

    private String logPath;
    private String grepPath;
    private StringBuilder consoleLog = new StringBuilder("");
    private String logLevel = "info";
    private Map<String, String> credentials = null;

    public Logalyzer() {

    }

    public Logalyzer(String log, String grep) {

        this.setLogPath(log);
        this.setGrepPath(grep);

    }

    public Logalyzer(String grep) throws LogException {
        this.setGrepPath(grep);
        String path = Logalyzer.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        path = path.substring(0, path.lastIndexOf("/") + 1);
        try {
            String decodedPath = URLDecoder.decode(path, "UTF-8");
            this.setLogPath(decodedPath.substring(1, decodedPath.length()));
        } catch (UnsupportedEncodingException e) {
            throw new LogException("Error: " + e.getMessage());
        }
    }

    public String getLogPath() {
        return logPath;
    }

    public void setLogPath(String logPath) {
        this.logPath = logPath;
    }

    public String getGrepPath() {
        return grepPath;
    }

    public void setGrepPath(String grepPath) {
        this.grepPath = grepPath;
    }

    public String getLogLevel() {
        return logLevel;
    }

    public void setLogLevel(String logLevel) {
        this.logLevel = logLevel;
    }

    public StringBuilder getConsoleLog() {
        return consoleLog;
    }

    public void setConsoleLog(StringBuilder consoleLog) {
        this.consoleLog = consoleLog;
    }

    public Map<String, String> getCredentials() {
        return credentials;
    }

    public void setCredentials(Map<String, String> credentials) {
        this.credentials = credentials;
    }

    public void displayToConsole(String message) {
        message = this.getLogLevel() + ":" + message;
        this.getConsoleLog().append(System.getProperty("line.separator")+message);
        System.out.println("******************************************************************");
        System.out.println("BEGINNING CONSOLE LOG");
        System.out.println("******************************************************************");
        System.out.println(this.getConsoleLog());
        System.out.println("******************************************************************");
        System.out.println("ENDING CONSOLE LOG");
        System.out.println("******************************************************************");
    }

    public static void main(String args[]) {
    }

    public StringBuilder searchJavaSession(String sessionId) throws LogException {
        try {
            StringBuilder output = new StringBuilder();
            if (!sessionId.isEmpty()) {
                output.append("Search result for pattern \"" + sessionId + "\":");
                String line;
                Process p = null;
                File file = new File(this.getLogPath());
                if (new File(this.getLogPath()).isDirectory()) {
                    this.displayToConsole("Running Command: " + this.getGrepPath() + " -r \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                    p = Runtime.getRuntime().exec(this.getGrepPath() + " -r --exclude-dir=session_captures \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                } else {
                    this.displayToConsole("Running Command: " + this.getGrepPath() + " \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                    p = Runtime.getRuntime().exec(this.getGrepPath() + " \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                }
                p.waitFor();
                BufferedReader bri = new BufferedReader(new InputStreamReader(p.getInputStream()));
                while ((line = bri.readLine()) != null) {
                    output.append(System.getProperty("line.separator") + line);
                }
                bri.close();
                if (output == null) {
                    BufferedReader bre = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                    while ((line = bre.readLine()) != null) {
                        output.append(line);
                    }
                    bre.close();
                }
                if (!isFilenameValid(sessionId) && sessionId.contains(":/bbIVR")) {
                    this.displayToConsole("Writing the file to save capture: " + sessionId.substring(0, 32) + ".txt");
                    writeToFile(output.toString(), "grep_for_" + sessionId.substring(0, 32));
                }
                return output;
            } else {
                return output.append("You didn't provide anything to search for man...");
            }

        } catch (
                Exception e
                )

        {
            throw new LogException("Error occurred: " + e.getMessage());
        }


    }

    public boolean isFilenameValid(String file) {
        File f = new File(file);
        try {
            f.getCanonicalPath();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void writeToFile(String content, String filename) throws LogException {
        try {
            File sessionDirectory = new File("." + File.separator + "session_captures");
            if (!sessionDirectory.exists()) {
                sessionDirectory.mkdir();
            }
            File file = new File(sessionDirectory + File.separator + filename + ".txt");
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(content);
            bw.close();
        } catch (IOException e) {
            throw new LogException("Error opening file: " + e.getMessage());
        }
    }

    public ArrayList<String> getSessionIdsFromLog(String pathToFile) throws LogException {
        try {
            File file = new File(pathToFile);
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line = br.readLine();
            ArrayList<String> javaSessionIds = new ArrayList<>();
            while (line != null) {
                line = br.readLine();
                if (line != null) {
                    if (line.contains(":/bbIVR")) {
                        if (!javaSessionIds.contains(extractSessionId(line))) {
                            javaSessionIds.add(extractSessionId(line));
                        }
                    }
                }

            }
            br.close();
            return javaSessionIds;
        } catch (FileNotFoundException e) {
            throw new LogException("File not found: " + e.getMessage());
        } catch (IOException e) {
            throw new LogException("IO Exception: " + e.getMessage());
        }
    }

    public String extractSessionId(String line) throws LogException {
        int sessionSuffixLoc = line.indexOf(":/bbIVR");
        return line.substring(sessionSuffixLoc - 32, sessionSuffixLoc + 7);
    }

    public Boolean sftpFromServer(String pathToGet, String usr, String host, String pwd) throws LogException {
        Session session = null;
        Channel channel = null;
        ChannelSftp channelSftp = null;

        try {
            JSch jsch = new JSch();
            session = jsch.getSession(usr, host, 22);
            session.setPassword(pwd);
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);
            session.connect();
            channel = session.openChannel("sftp");
            channel.connect();
            channelSftp = (ChannelSftp) channel;
            channelSftp.cd(pathToGet);
            Vector<ChannelSftp.LsEntry> logs = channelSftp.ls(pathToGet + "/*.log");
            Vector<ChannelSftp.LsEntry> logGZIPs = channelSftp.ls(pathToGet + "/*.gz");
            this.displayToConsole("LOG files found: " + logs);
            this.displayToConsole("GZIP Files found: " + logGZIPs);
            Vector<ChannelSftp.LsEntry> allFiles = new Vector<ChannelSftp.LsEntry>();
            allFiles.addAll(logs);
            allFiles.addAll(logGZIPs);
            byte[] buffer = new byte[1024];
            for (ChannelSftp.LsEntry c : allFiles) {
                this.displayToConsole("About to download file: " + c.getFilename());
                File newFile = null;
                if (this.logPath == null) {
                    this.displayToConsole("Trying to create file: " + System.getProperty("user.dir") + System.getProperty("file.separator") + c.getFilename());
                    newFile = new File(System.getProperty("user.dir") + System.getProperty("file.separator") + c.getFilename());
                } else {
                    newFile = new File(this.logPath + "/" + c.getFilename());

                }
                BufferedInputStream bis = new BufferedInputStream(channelSftp.get(c.getFilename()));
                OutputStream os = new FileOutputStream(newFile);
                BufferedOutputStream bos = new BufferedOutputStream(os);
                int readCount;
                while ((readCount = bis.read(buffer)) > 0) {
                    this.displayToConsole("Writing: ");
                    bos.write(buffer, 0, readCount);
                }
                bis.close();
                bos.close();
            }
            this.displayToConsole("Finished retrieving all Files from SFTP");
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new LogException("An error occurred: " + ex.getMessage());
        }
    }

    public Map<String, String> parseSSHCredentials(String creds) throws LogException{
        HashMap <String, String> credentials = new HashMap<String, String>() {
        };
        try{
            credentials.put("username", creds.substring(0, creds.indexOf(":")));
            credentials.put("password", creds.substring(creds.indexOf(":")+1, creds.indexOf("@")));
            credentials.put("host", creds.substring(creds.indexOf("@")+1, creds.lastIndexOf(":")));
            credentials.put("file", creds.substring(creds.lastIndexOf(":")+1, creds.length()));
            return credentials;
        }
        catch (NullPointerException | StringIndexOutOfBoundsException e){
            throw new LogException("Error parsing SSH credentials, format is \"username:password@host:pathToFiles\" : " + e.getMessage());
        }

    }

    public Boolean unZipLogs(String pathToTar) throws LogException{
        try{
            if(isFilenameValid(pathToTar) && new File(pathToTar).isDirectory()){
                Process p = Runtime.getRuntime().exec(pathToTar + System.getProperty("file.separator")+"tar.exe ");
            }
            else{
                throw new LogException("Path error, please provide valid directory path for Tar.exe");
            }

            return true;
        }
        catch(IOException e){
            throw new LogException("Error occurred: " + e.getMessage());
        }

    }
}
