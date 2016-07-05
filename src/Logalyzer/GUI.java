package Logalyzer;

import org.apache.http.NameValuePair;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by rhenderson on 6/28/2016.
 */
public class GUI extends JFrame {
    private JTextArea displayConsole = new JTextArea(40, 85);
    private JTextArea consoleLog = new JTextArea(10, 20);
    private JScrollPane consolePane = new JScrollPane(displayConsole);
    private JScrollPane consoleLogPane = new JScrollPane(consoleLog);

    private JTextField pattern = new JTextField(50);
    private JTextField grep = new JTextField(50);
    private JTextField log = new JTextField(50);
    private JTextField SFTPInfo = new JTextField(50);
    private JButton executeButton = new JButton();
    private JButton pullLogsFromServer = new JButton();
    private JButton unZipLogs = new JButton();
    private HashMap<String, Thread> guiThreads = new HashMap<>();

    Logalyzer logalyzer = null;
    private StringBuilder runLog = new StringBuilder();


    public GUI(String titleOfWindow, int width, int height) {
        try {
            logalyzer = new Logalyzer(grep.getText());
            initGUI(width, height, titleOfWindow);
            logalyzer.displayToConsole("New Logalyzer Initialized with: " + grep.getText());
            logalyzer.setCredentials(logalyzer.parseSSHCredentials(SFTPInfo.getText()));
            logalyzer.displayToConsole("Logalyzer set credentials: " + logalyzer.getCredentials().toString());
            logalyzer.displayToConsole("Initializing GUI..");
            runGUI();
            logalyzer.displayToConsole("Initalizing Threads...");
            this.guiThreads = initThreads();
            logalyzer.displayToConsole("Starting Console Refresh thread");
            startThreads(this.guiThreads.get("console"));
            logalyzer.displayToConsole("Initializing Event Action Listeners...");
            addActionListeners();
        } catch (LogException e) {
            logalyzer.displayToConsole("Could not create a Logalyzer: " + e.getMessage());
        }


    }

    private void initGUI(int width, int height, String titleOfWindow) {
        setSize(width, height);
        setTitle(titleOfWindow);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BoxLayout(this.getContentPane(), BoxLayout.Y_AXIS));
        consoleLogPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        consoleLogPane.setPreferredSize(new Dimension(1150, 200));
        displayConsole.setEditable(false);
        //pattern.setText("59BF2C55C1440A8FEEEBB1538D9D6064:/bbIVR");
        pattern.setText("59BF2C55C1440A8FEEE881338D9D6064:/bbIVR");
        //pattern.setText("Test123");
        executeButton.setText("Pull logs for JAVASESSIONID");
        pullLogsFromServer.setText("Download logs from Server");
        unZipLogs.setText("Unzip Logs");
        SFTPInfo.setText("reaperman:13371337@rh.rdctech.com:/home/reaperman/logs/rh.rdctech.com/http");
        consoleLog.setLineWrap(true);
        consoleLog.setWrapStyleWord(true);
        grep.setText("C:\\cygwin64\\bin\\grep.exe");
        displayConsole.setLineWrap(true);
        log.setText(logalyzer.getLogPath());
    }

    private void runGUI() {
        revalidate();
        setVisible(true);
        add(new Label("Location of GREP:"));
        add(grep);
        add(new Label("Log Searching Directory:"));
        add(log);
        add(new Label("Pattern:"));
        add(pattern);
        add(new Label("SFTP Credentials:"));
        add(SFTPInfo);
        add(new Label("Display of Search:"));
        add(consolePane);
        add(new Label("Command Log:"));
        add(consoleLogPane);
        add(executeButton);
        add(pullLogsFromServer);
        add(unZipLogs);
    }

    private void addActionListeners() {
        executeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                logalyzer.setGrepPath(grep.getText());
                logalyzer.setLogPath(log.getText());
                logalyzer.displayToConsole(System.getProperty("line.separator") + "Searching for Java Session ID: " + pattern.getText());
                try {
                    StringBuilder searchReturn = logalyzer.searchJavaSession(pattern.getText().toString());
                    if (searchReturn.toString().equalsIgnoreCase("")) {
                        displayConsole.setText("No pattern found inside that path");
                    } else {
                        displayConsole.setText(searchReturn.toString());
                    }
                } catch (LogException err) {
                    displayConsole.setText("Error occurred: " + err.getMessage());
                }
            }
        });
        pullLogsFromServer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                createNewThread(guiThreads.get("grabLogs")).start();
            }
        });
        /*unZipLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

            }
        });*/
    }

    private HashMap<String, Thread> initThreads() {
        HashMap<String, Thread> threads = new HashMap<>();
        final Thread refreshConsole = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    consoleLog.setText(logalyzer.getConsoleLog().toString());
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        logalyzer.displayToConsole("Error: " + e.getMessage());
                    }
                }
            }
        });
        final Thread grabLogs = new Thread(new Runnable() {
            @Override
            public void run() {
                logalyzer.displayToConsole("Starting Thread to acquire logs via SFTP...");
                try {
                    logalyzer.setCredentials(logalyzer.parseSSHCredentials(SFTPInfo.getText()));
                    logalyzer.displayToConsole("Successfully parsed and set SSH Credentials: " + logalyzer.getCredentials().toString());

                    logalyzer.displayToConsole("Beginning retrieval of Files over SFTP...");
                    logalyzer.sftpFromServer(logalyzer.getCredentials().get("file"), logalyzer.getCredentials().get("username"), logalyzer.getCredentials().get("host"), logalyzer.getCredentials().get("password"));
                } catch (LogException err) {
                    logalyzer.displayToConsole("Error while trying to pull logs from Server: " + err.getMessage());
                }
            }
        });
        threads.put("console", refreshConsole);
        threads.put("grabLogs", grabLogs);
        return threads;
    }

    private void startThreads(Thread thread) {
        thread.start();
    }

    private Thread createNewThread(Thread thread){
        return new Thread(thread);
    }
}
