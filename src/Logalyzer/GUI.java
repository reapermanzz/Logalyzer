package Logalyzer;

import org.apache.http.NameValuePair;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

/**
 * Created by rhenderson on 6/28/2016.
 */
public class GUI extends JFrame {
    private JTextArea displayConsole = new JTextArea(40, 85);
    private JTextArea consoleLog = new JTextArea(10, 20);
    private JScrollPane consolePane = new JScrollPane(displayConsole);

    private JTextField pattern = new JTextField(50);
    private JTextField grep = new JTextField(50);
    private JTextField log = new JTextField(50);
    private JButton executeButton = new JButton();
    Logalyzer logalyzer = null;
    private StringBuilder runLog = new StringBuilder();


    public GUI(String titleOfWindow, int width, int height){
        setSize(width, height);
        setTitle(titleOfWindow);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());
        displayConsole.setEditable(false);
        //pattern.setText("59BF2C55C1440A8FEEEBB1538D9D6064:/bbIVR");
        pattern.setText("59BF2C55C1440A8FEEE881338D9D6064:/bbIVR");
        //pattern.setText("Test123");
        executeButton.setText("Pull log of Call");
        grep.setText("C:\\cygwin64\\bin\\grep.exe");

        displayConsole.setLineWrap(true);
        try{
            logalyzer = new Logalyzer(grep.getText());
        }
        catch(LogException e){
            displayConsole.setText("Could not create a Logalyzer: " + e.getMessage());
        }
        log.setText(logalyzer.getLogPath());
        setVisible(true);
        add(grep);
        add(log);
        add(pattern);
        add(consolePane);
        add(consoleLog);
        add(executeButton);

        executeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                logalyzer.setGrepPath(grep.getText());
                logalyzer.setLogPath(log.getText());
                runLog.append(System.getProperty("line.separator") + "Searching for Java Session ID: " + pattern.getText());
                consoleLog.setText(runLog.toString());
                try{
                    StringBuilder searchReturn = logalyzer.searchJavaSession(pattern.getText().toString());
                    if (searchReturn.toString().equalsIgnoreCase("")){
                        displayConsole.setText("No pattern found inside that path");
                    }
                    else{
                        displayConsole.setText(searchReturn.toString());
                    }
                }
                catch(LogException err){
                    displayConsole.setText("Error occurred: " + err.getMessage());
                }
            }
        });
    }

    public void setConsole(){

    }

}
