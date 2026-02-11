package loganalyzer;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class AdminTargetingRule implements DetectionRule {

    private final Set<String> suspiciousUsers = new HashSet<>();

    public AdminTargetingRule() {
        suspiciousUsers.add("admin");
        suspiciousUsers.add("root");
        suspiciousUsers.add("administrator");
    }

    @Override
    public String getName() {
        return "Admin/Root Targeting";
    }

    @Override
    public Optional<Alert> match(LogEntry entry, RuleContext context) {
        if (!entry.isLoginFailure()) {
            return Optional.empty();
        }

        String user = entry.getUser();
        if (user == null) {
            return Optional.empty();
        }

        if (suspiciousUsers.contains(user.toLowerCase())) {
            String desc = "Failed login attempt for privileged account user=" + user
                    + " from ip=" + safe(entry.getIp());
            return Optional.of(new Alert(getName(), Severity.HIGH, desc, entry));
        }

        return Optional.empty();
    }

    private String safe(String s) {
        return (s == null) ? "unknown" : s;
    }
}
