package loganalyzer;

import javax.swing.SwingUtilities;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new LogAnalyzerFrame().setVisible(true));
    }
}
