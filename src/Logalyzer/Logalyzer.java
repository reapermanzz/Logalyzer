package Logalyzer;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import net.sf.jftp.*;
import net.sf.jftp.net.FtpClient;
import net.sf.jftp.net.FtpConnection;
import net.sf.jftp.net.FtpTransfer;

import java.io.*;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Vector;


/**
 * Created by rhenderson on 6/28/2016.
 */
public class Logalyzer {

    private String logPath;
    private String grepPath;

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
                    System.out.println("Running Command: " + this.getGrepPath() + " -r \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                    p = Runtime.getRuntime().exec(this.getGrepPath() + " -r --exclude-dir=session_captures \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
                } else {
                    System.out.println("Running Command: " + this.getGrepPath() + " \"" + sessionId + "\" " + "\"" + this.getLogPath() + "\"");
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
                    System.out.println("Writing the file to save capture: " + sessionId.substring(0, 32) + ".txt");
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

    /*public Boolean sshLogFilesFromServer(String pathToSFTP, String pathToGet, String usr, String host, String pwd) throws LogException {
        if (pathToSFTP != null && isFilenameValid(pathToSFTP)) {
            try {
                System.out.println("Running command...: " + pathToSFTP + " " + usr + "@" + host + ":" + pathToGet);
                Process p = Runtime.getRuntime().exec(pathToSFTP + " " + usr + "@" + host + ":" + pathToGet);
                boolean finishedInteracting = true;
                BufferedReader bri = null;
                BufferedWriter brw = null;
                StringBuilder inputStream = new StringBuilder();
                while (finishedInteracting) {

                    System.out.println("Starting interactive streams...");

                    OutputStream out = p.getOutputStream();
                    out.write("13371337");
                    //read the output of the command currently
                    bri = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String line;


                    while (bri.ready() && (line = bri.readLine()) != null) {
                        System.out.println("Printing input stream line...");
                        inputStream.append(System.lineSeparator() + line);
                        System.out.println(line);
                    }
                    if (inputStream.length() == 0) {
                        System.out.println("InputStream is null");
                        BufferedReader bre = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                        while ((line = bre.readLine()) != null) {
                            inputStream.append(System.lineSeparator() + line);
                        }
                        throw new LogException("Error while running SFTP command: " + inputStream.toString());
                    }
                    System.out.println("typing the password...");

                    //check if the process has finished running
                    try {
                        p.exitValue();
                        System.out.println("Process has finished running");
                        finishedInteracting = false;
                    } catch (IllegalThreadStateException itse) {
                        //keep on running
                    }
                    break;
                }
                //close the streams
                bri.close();
                brw.close();

            } catch (IOException e) {
                throw new LogException("IO Exception trying to run SFTP Command: " + e.getMessage());
            }
            return true;
        }
        throw new LogException("You didn't give me a valid path");
    }*/

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
            System.out.println("GZIPS: " + logGZIPs);
            Vector<ChannelSftp.LsEntry> allFiles = new Vector <ChannelSftp.LsEntry>();
            allFiles.addAll(logs);
            allFiles.addAll(logGZIPs);
            byte[] buffer = new byte[1024];
            for(ChannelSftp.LsEntry c: allFiles){
                System.out.println("About to download file: " + c.getFilename());
                BufferedInputStream bis = new BufferedInputStream(channelSftp.get(c.getFilename()));
                File newFile = new File(this.logPath + "/" + c.getFilename());
                OutputStream os = new FileOutputStream(newFile);
                BufferedOutputStream bos = new BufferedOutputStream(os);
                int readCount;
                while ((readCount = bis.read(buffer)) > 0) {
                    System.out.println("Writing: ");
                    bos.write(buffer, 0, readCount);
                }
                bis.close();
                bos.close();
            }

            return true;
        } catch (Exception ex) {
            System.out.println("An error occurred: " + ex.getMessage());
            ex.printStackTrace();
            return false;
        }
    }
}
