package loganalyzer;

import java.util.Optional;

public interface DetectionRule {
    String getName();
    Optional<Alert> match(LogEntry entry, RuleContext context);
}
