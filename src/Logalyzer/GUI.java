package Logalyzer;

import javax.swing.*;
import java.awt.*;

/**
 * Created by rhenderson on 6/28/2016.
 */
public class GUI extends JFrame {
    private JTextArea displayConsole = new JTextArea(40, 85);
    private JScrollPane consolePane = new JScrollPane(displayConsole);

    public JTextArea getDisplayConsole() {
        return displayConsole;
    }

    public void setDisplayConsole(JTextArea displayConsole) {
        this.displayConsole = displayConsole;
    }

    private JTextField httpsURLInput = new JTextField(50);
    private JButton executeButton = new JButton();

    public GUI(String titleOfWindow, int width, int height){
        setSize(width, height);
        setTitle(titleOfWindow);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new FlowLayout());
        displayConsole.setEditable(false);
        httpsURLInput.setText("59BF2C55C1440A8FEEEBB1538D9D6064:/bbIVR");
        executeButton.setText("Pull log of Call");
        displayConsole.setLineWrap(true);
        setVisible(true);
        add(httpsURLInput);
        add(consolePane);
        add(executeButton);
    }

    public void reloadGUI(){

    }

}
