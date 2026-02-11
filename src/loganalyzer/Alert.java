package loganalyzer;

public class Alert {
    private final String ruleName;
    private final Severity severity;
    private final String description;
    private final LogEntry entry;

    public Alert(String ruleName, Severity severity, String description, LogEntry entry) {
        this.ruleName = ruleName;
        this.severity = severity;
        this.description = description;
        this.entry = entry;
    }

    public String getRuleName() { return ruleName; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }
    public LogEntry getEntry() { return entry; }
}
