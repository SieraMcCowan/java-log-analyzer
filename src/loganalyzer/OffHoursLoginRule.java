package loganalyzer;

import java.time.LocalTime;
import java.util.Optional;

public class OffHoursLoginRule implements DetectionRule {

    private final LocalTime start;
    private final LocalTime end;

    /**
     * Flags successful logins during "off hours".
     * Default use: start=00:00, end=04:59
     */
    public OffHoursLoginRule(LocalTime start, LocalTime end) {
        this.start = start;
        this.end = end;
    }

    @Override
    public String getName() {
        return "Off-Hours Login";
    }

    @Override
    public Optional<Alert> match(LogEntry entry, RuleContext context) {
        if (!entry.isLoginSuccess()) {
            return Optional.empty();
        }

        LocalTime t = entry.getTimestamp().toLocalTime();
        if (isBetweenInclusive(t, start, end)) {
            String user = safe(entry.getUser());
            String ip = safe(entry.getIp());
            String desc = "Login success during off-hours user=" + user + " ip=" + ip + " time=" + t;
            return Optional.of(new Alert(getName(), Severity.MEDIUM, desc, entry));
        }

        return Optional.empty();
    }

    private boolean isBetweenInclusive(LocalTime time, LocalTime start, LocalTime end) {
        // Handles normal ranges like 00:00-04:59.
        // (If you ever wanted a wraparound range like 22:00-02:00, you'd tweak this.)
        return !time.isBefore(start) && !time.isAfter(end);
    }

    private String safe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }
}
