package Logalyzer;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/**
 * Created by ReaperMan on 7/5/2016.
 */
public class ThreadMonitor extends Thread {
    boolean report = true;
    boolean terminate = false;
    private ArrayList<Thread> allThreads = new ArrayList<>();
    private Logalyzer logalyzer = new Logalyzer();

    ThreadMonitor(ArrayList<Thread> threads, Logalyzer log) {
        this.allThreads = threads;
        this.logalyzer = log;

    }

    public void run() {
        String thrdName = Thread.currentThread().getName();
        this.logalyzer.displayToConsole(thrdName + " starting.");
        try {
            while (!terminate) {
                while (report) {
                    Thread.sleep(3000);
                    this.logalyzer.displayToConsole("***Thread Status Report***");
                    for (Thread t : this.allThreads) {
                        this.logalyzer.displayToConsole("Thread Name: " + t.getName() + " Status: " + t.getState() + " Alive: " + t.isAlive());
                    }
                    this.logalyzer.displayToConsole("***END of Thread Status Report***");
                }
                Thread.sleep(3000);
            }
        } catch (Exception exc) {
            this.logalyzer.displayToConsole(thrdName + " interrupted.");
        }
        this.logalyzer.displayToConsole(thrdName + " terminating.");
    }

    synchronized void startWait() {
        try {
            while (!report) wait();
        } catch (InterruptedException exc) {
            this.logalyzer.displayToConsole("wait() interrupted");
        }
    }

    synchronized void notice() {
        report = true;
        notify();
    }

    void showThreadStatus(Thread thrd) {
        this.logalyzer.displayToConsole(thrd.getName() + "Alive:=" + thrd.isAlive() + "State:=" + thrd.getState());
    }
}