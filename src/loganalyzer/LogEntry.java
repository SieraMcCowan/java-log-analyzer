package loganalyzer;

import java.time.LocalDateTime;

public class LogEntry {
    private final LocalDateTime timestamp;
    private final String level;
    private final String action;
    private final String outcome;
    private final String user;
    private final String ip;
    private final String rawLine;
    private final LogFormat format;

    public LogEntry(LocalDateTime timestamp,
                    String level,
                    String action,
                    String outcome,
                    String user,
                    String ip,
                    String rawLine,
                    LogFormat format) {
        this.timestamp = timestamp;
        this.level = level;
        this.action = action;
        this.outcome = outcome;
        this.user = user;
        this.ip = ip;
        this.rawLine = rawLine;
        this.format = format;
    }

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getLevel() { return level; }
    public String getAction() { return action; }
    public String getOutcome() { return outcome; }
    public String getUser() { return user; }
    public String getIp() { return ip; }
    public String getRawLine() { return rawLine; }
    public LogFormat getFormat() { return format; }

    public boolean isLoginFailure() {
        return "Login".equalsIgnoreCase(action) && "failed".equalsIgnoreCase(outcome);
    }

    public boolean isLoginSuccess() {
        return "Login".equalsIgnoreCase(action) && "success".equalsIgnoreCase(outcome);
    }
}
