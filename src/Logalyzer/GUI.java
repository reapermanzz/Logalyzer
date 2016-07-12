package Logalyzer;

import org.apache.http.NameValuePair;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
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
    private JTextField gzipPath = new JTextField(50);
    private JButton executeButton = new JButton();
    private JButton pullLogsFromServer = new JButton();
    private JButton threadCheck = new JButton();
    private JButton unZipLogs = new JButton();
    private HashMap<String, Thread> guiThreadsTemplate = new HashMap<>();
    private ArrayList<Thread> runningThreads = new ArrayList<>();
    private ThreadMonitor threadMon;

    Logalyzer logalyzer = null;
    private StringBuilder runLog = new StringBuilder();


    public GUI(String titleOfWindow, int width, int height) {
        try {
            this.logalyzer = new Logalyzer(grep.getText());
            initGUI(width, height, titleOfWindow);
            logalyzer.displayToConsole("New Logalyzer Initialized with: " + grep.getText());
            logalyzer.setCredentials(logalyzer.parseSSHCredentials(SFTPInfo.getText()));
            logalyzer.displayToConsole("Logalyzer set credentials: " + logalyzer.getCredentials().toString());

            logalyzer.displayToConsole("Initializing GUI..");
            runGUI();

            logalyzer.displayToConsole("Initalizing Threads...");
            this.guiThreadsTemplate = initThreads();

            logalyzer.displayToConsole("Starting Console Refresh thread");
            Thread consoleThread = new Thread(guiThreadsTemplate.get("console"));
            consoleThread.setName("Console Thread\"" +new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
            createNewThread(consoleThread).start();
            logalyzer.displayToConsole("Initializing Event Action Listeners...");
            addActionListeners();

            logalyzer.displayToConsole("Creating ThreadMonitor thread...");
            ThreadMonitor threadMon = new ThreadMonitor(runningThreads, logalyzer);
            logalyzer.displayToConsole("Starting ThreadMonitor thread with reporting turned off, click Check Thread Status button to enable...");
            threadMon.setName("Thread Monitor\"" +new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
            threadMon.report = false;
            this.threadMon = threadMon;
            createNewThread(threadMon).start();
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
        executeButton.setText("Find Calls");
        pullLogsFromServer.setText("Download logs from Server");
        unZipLogs.setText("Unzip Logs");
        SFTPInfo.setText("username:password@host.com:/path/to/logs");
        consoleLog.setLineWrap(true);
        consoleLog.setWrapStyleWord(true);
        grep.setText("C:\\cygwin64\\bin\\");
        displayConsole.setLineWrap(true);
        log.setText(logalyzer.getLogPath());
        threadCheck.setText("Check Thread Status");
        gzipPath.setText("C:\\cygwin64\\bin\\");
    }

    private void runGUI() {
        revalidate();
        setVisible(true);
        add(new Label("Location of GZIP"));
        add(gzipPath);
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
        add(threadCheck);
    }

    private void addActionListeners() {
        executeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                logalyzer.setGrepPath(grep.getText());
                logalyzer.setLogPath(log.getText());
                logalyzer.displayToConsole(System.getProperty("line.separator") + "Searching for Java Session ID: " + pattern.getText());
                Thread grep = createNewThread(guiThreadsTemplate.get("grep"));
                grep.setName("Grep Thread\"" +new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
                grep.start();

            }
        });
        pullLogsFromServer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Thread grabLogs = createNewThread(guiThreadsTemplate.get("grabLogs"));
                grabLogs.setName("Grablogs Thread\"" +new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
                grabLogs.start();
            }
        });
        unZipLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                logalyzer.setGzipPath(gzipPath.getText());
                Thread unZipLogs = createNewThread(guiThreadsTemplate.get("unzip"));
                unZipLogs.setName("GZIP Thread\""+new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
                unZipLogs.start();
            }
        });
        threadCheck.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if(threadMon.report){threadMon.report = false;}
                else{
                    threadMon.report = true;
                }
            }
        });
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
                    if(SFTPInfo.getText().equalsIgnoreCase("QA")){
                        logalyzer.displayToConsole("Beginning retrieval of Files over SFTP from QA...");
                        logalyzer.sftpFromServer("/usr/local/apache-tomcat-7.0.61/webapps/bbIVR/data/log", "root", "qvxml001ykf", "ucR00t!");
                    }
                    else if(SFTPInfo.getText().equalsIgnoreCase("PRODYKF")){
                        logalyzer.displayToConsole("Beginning retrieval of Files over SFTP from PRODYKF...");
                        logalyzer.sftpFromServer("/usr/local/apache-tomcat-7.0.61/webapps/bbIVR/data/log", "root", "vxml010ykf", "ucR00t!");
                    }
                    else if(SFTPInfo.getText().equalsIgnoreCase("PRODCNC")){
                        logalyzer.displayToConsole("Beginning retrieval of Files over SFTP from PRODCNC...");
                        logalyzer.sftpFromServer("/usr/local/apache-tomcat-7.0.61/webapps/bbIVR/data/log", "root", "vxml010cnc", "ucR00t!");
                    }
                    else{
                        logalyzer.setCredentials(logalyzer.parseSSHCredentials(SFTPInfo.getText()));
                        logalyzer.displayToConsole("Successfully parsed and set SSH Credentials: " + logalyzer.getCredentials().toString());
                        logalyzer.displayToConsole("Beginning retrieval of Files over SFTP....");
                        logalyzer.sftpFromServer(logalyzer.getCredentials().get("file"), logalyzer.getCredentials().get("username"), logalyzer.getCredentials().get("host"), logalyzer.getCredentials().get("password"));
                    }

                } catch (LogException err) {
                    logalyzer.displayToConsole("Error while trying to pull logs from Server: " + err.getMessage());
                }
            }
        });
        final Thread grep = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if(!pattern.getText().contains(":/bbIVR")){
                        logalyzer.displayToConsole("Compiling available sessionIDs based on ANI search...");
                        StringBuilder searchReturn = logalyzer.searchJavaSession(pattern.getText());
                        Thread finder = new Thread(guiThreadsTemplate.get("finder"));
                        finder.setName("Finder GUI thread\""+new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
                        createNewThread(finder).start();
                        if (searchReturn.toString().equalsIgnoreCase("")) {
                            displayConsole.setText("No pattern found inside that path");
                        } else {
                            displayConsole.setText(searchReturn.toString());
                        }
                    }
                    else{
                        logalyzer.displayToConsole("Starting GREP search thread...");
                        StringBuilder searchReturn = logalyzer.searchJavaSession(pattern.getText());
                        if (searchReturn.toString().equalsIgnoreCase("")) {
                            displayConsole.setText("No pattern found inside that path");
                        } else {
                            displayConsole.setText(searchReturn.toString());
                        }
                    }

                } catch (LogException err) {
                    logalyzer.displayToConsole("Error occurred: " + err.getMessage());
                }
            }
        });
        final Thread unzip = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    logalyzer.displayToConsole("Starting GZIP thread to extract logs...");
                    if(logalyzer.unZipLogs(gzipPath.getText())){
                        unZipLogs.setBackground(new Color(0, 255, 0));
                    }
                    else{
                        unZipLogs.setBackground(new Color(255, 0, 0));
                    }
                } catch (LogException err) {
                    logalyzer.displayToConsole("Error occurred: " + err.getMessage());
                }
            }
        });
        final Thread finder = new Thread(new Runnable() {
            @Override
            public void run() {
                logalyzer.displayToConsole("Starting Finder GUI thread...");
                try{
                    startFinderGUI(logalyzer.getSessionIdsFromSearch(logalyzer.searchJavaSession(pattern.getText())));
                }
                catch(LogException e){
                    logalyzer.displayToConsole("Error occurred: " + e.getMessage());
                }
            }
        });

        threads.put("console", refreshConsole);
        threads.put("grabLogs", grabLogs);
        threads.put("grep", grep);
        threads.put("unzip", unzip);
        threads.put("finder", finder);
        return threads;
    }

    private Thread createNewThread(Thread thread) {
        Thread newThread = new Thread(thread, thread.getName());
        runningThreads.add(newThread);
        return newThread;
    }

    private void startFinderGUI(final ArrayList<String>selections){
        JFrame ng = new JFrame("Call Finder GUI");
        ng.setDefaultCloseOperation(ng.DISPOSE_ON_CLOSE);
        JPanel jSessionsSelectionPanel = new JPanel();
        jSessionsSelectionPanel.setLayout(new GridLayout(2, 0));
        JList sessionsListSelector = new JList(selections.toArray());
        jSessionsSelectionPanel.add(new JScrollPane(sessionsListSelector));
        Label info = new Label("Above is a selection of unique calls I found for \"" + pattern.getText() + "\", double-click one to pull the whole call...");
        info.setSize(3, 2);
        jSessionsSelectionPanel.add(info);
        final Container pane = ng.getContentPane();
        pane.add(jSessionsSelectionPanel, BorderLayout.NORTH);
        ng.pack();
        ng.setVisible(true);
        sessionsListSelector.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent evt) {
                JList list = (JList)evt.getSource();
                if (evt.getClickCount() == 2) {
                    logalyzer.displayToConsole("Selection detected via Finder GUI: " + selections.get(list.getSelectedIndex()));
                    pattern.setText(selections.get(list.getSelectedIndex()));
                    Thread grep = createNewThread(guiThreadsTemplate.get("grep"));
                    grep.setName("Grep Thread\"" +new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())+"\"");
                    grep.start();
                }
            }
        });


        ArrayList<Component> jframeComponents = getAllComponents(pane);
    }

    private static ArrayList<Component> getAllComponents(final Container c) {
        Component[] comps = c.getComponents();
        ArrayList<Component> compList = new ArrayList<Component>();
        for (Component comp : comps) {
            compList.add(comp);
            if (comp instanceof Container)
                compList.addAll(getAllComponents((Container) comp));
        }
        return compList;
    }
}
