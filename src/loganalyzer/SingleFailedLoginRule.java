package loganalyzer;

import java.util.Optional;
import java.util.Set;

public class SingleFailedLoginRule implements DetectionRule {

    private final Set<String> privilegedUsers = Set.of("admin", "root", "administrator");

    @Override
    public String getName() {
        return "Single Failed Login";
    }

    @Override
    public Optional<Alert> match(LogEntry entry, RuleContext context) {
        if (!entry.isLoginFailure()) {
            return Optional.empty();
        }

        // Avoid duplicating the HIGH admin/root alerts
        String user = entry.getUser();
        if (user != null && privilegedUsers.contains(user.toLowerCase())) {
            return Optional.empty();
        }

        String desc = "Single failed login user=" + safe(entry.getUser()) + " ip=" + safe(entry.getIp());
        return Optional.of(new Alert(getName(), Severity.LOW, desc, entry));
    }

    private String safe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }
}
