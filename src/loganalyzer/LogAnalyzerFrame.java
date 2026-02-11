package loganalyzer;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Path;
import java.time.LocalTime;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;

public class LogAnalyzerFrame extends JFrame {

    private final JComboBox<LogFormat> formatBox = new JComboBox<>(LogFormat.values());
    private final JComboBox<SeverityFilter> severityBox = new JComboBox<>(SeverityFilter.values());
    private final JButton loadBtn = new JButton("Load File");
    private final JButton analyzeBtn = new JButton("Analyze");
    private final JButton exportBtn = new JButton("Export CSV");

    private final JTextArea summaryArea = new JTextArea(10, 70);
    private final AlertTableModel tableModel = new AlertTableModel();
    private final JTable table = new JTable(tableModel);

    private Path loadedFile;
    private ParserResult lastParse;
    private AnalysisResult lastAnalysis;

    public LogAnalyzerFrame() {
        super("Log Analyzer");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Format:"));
        top.add(formatBox);
        top.add(loadBtn);
        top.add(analyzeBtn);
        top.add(new JLabel("Filter severity:"));
        top.add(severityBox);
        top.add(exportBtn);

        add(top, BorderLayout.NORTH);

        summaryArea.setEditable(false);
        JScrollPane summaryScroll = new JScrollPane(summaryArea);

        JScrollPane tableScroll = new JScrollPane(table);

        // Color-code rows by severity
        table.setDefaultRenderer(Object.class, new SeverityColorRenderer(tableModel));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, summaryScroll, tableScroll);
        split.setResizeWeight(0.35);
        add(split, BorderLayout.CENTER);

        analyzeBtn.setEnabled(false);
        exportBtn.setEnabled(false);

        severityBox.setSelectedItem(SeverityFilter.ALL);

        loadBtn.addActionListener(e -> onLoad());
        analyzeBtn.addActionListener(e -> onAnalyze());
        exportBtn.addActionListener(e -> onExport());
        severityBox.addActionListener(e -> applySeverityFilter());

        pack();
        setLocationRelativeTo(null);
    }

    private void onLoad() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File f = chooser.getSelectedFile();
        loadedFile = f.toPath();

        summaryArea.setText("Loaded file:\n" + loadedFile + "\n");
        analyzeBtn.setEnabled(true);
        exportBtn.setEnabled(false);
        tableModel.setAlerts(List.of());
        lastParse = null;
        lastAnalysis = null;
    }

    private void onAnalyze() {
        if (loadedFile == null) return;

        try {
            ILogParser parser = (formatBox.getSelectedItem() == LogFormat.AUTH)
                    ? new AuthLogParser()
                    : new StructuredLogParser();

            lastParse = parser.parse(loadedFile);

            AnalyzerEngine engine = new AnalyzerEngine();

            // Existing HIGH rules
            engine.addRule(new AdminTargetingRule());
            engine.addRule(new BruteForceRule(5, 5));

            // NEW MEDIUM + LOW rules
            engine.addRule(new OffHoursLoginRule(LocalTime.of(0, 0), LocalTime.of(4, 59)));
            engine.addRule(new SingleFailedLoginRule());

            lastAnalysis = engine.analyze(lastParse.getEntries());

            String summary = ReportPrinter.buildSummaryText(lastParse.getStats(), lastParse.getEntries(), lastAnalysis);
            summaryArea.setText(summary);

            exportBtn.setEnabled(true);
            applySeverityFilter();

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Analyze error:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void applySeverityFilter() {
        if (lastAnalysis == null) return;

        SeverityFilter selected = (SeverityFilter) severityBox.getSelectedItem();
        if (selected == null) selected = SeverityFilter.ALL;

        List<Alert> filtered;

        if (selected == SeverityFilter.ALL) {
            filtered = lastAnalysis.getAlerts();
        } else {
            final Severity target = toSeverity(selected);
            filtered = lastAnalysis.getAlerts().stream()
                    .filter(a -> a.getSeverity() == target)
                    .collect(Collectors.toList());
        }

        tableModel.setAlerts(filtered);
    }

    private Severity toSeverity(SeverityFilter f) {
        switch (f) {
            case LOW: return Severity.LOW;
            case MEDIUM: return Severity.MEDIUM;
            case HIGH: return Severity.HIGH;
            default: return Severity.LOW; // not used for ALL
        }
    }

    private void onExport() {
        if (lastAnalysis == null) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("alerts.csv"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;

        try {
            CsvExporter.exportAlerts(chooser.getSelectedFile().toPath(), lastAnalysis.getAlerts());
            JOptionPane.showMessageDialog(this, "Exported CSV successfully.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export error:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // --- Renderer to color-code rows by severity ---
    private static class SeverityColorRenderer extends DefaultTableCellRenderer {

        private final AlertTableModel model;

        SeverityColorRenderer(AlertTableModel model) {
            this.model = model;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table,
                                                      Object value,
                                                      boolean isSelected,
                                                      boolean hasFocus,
                                                      int row,
                                                      int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (isSelected) {
                // keep default selection coloring
                return c;
            }

            Alert alert = model.getAlertAt(row);
            if (alert == null) {
                c.setBackground(table.getBackground());
                return c;
            }

            switch (alert.getSeverity()) {
                case HIGH:
                    c.setBackground(new java.awt.Color(255, 220, 220)); // light red
                    break;
                case MEDIUM:
                    c.setBackground(new java.awt.Color(255, 245, 204)); // light yellow
                    break;
                case LOW:
                default:
                    c.setBackground(new java.awt.Color(230, 245, 255)); // light blue
                    break;
            }

            return c;
        }
    }
}
