package loganalyzer;

import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.Optional;

public class BruteForceRule implements DetectionRule {

    private final int threshold;
    private final int windowMinutes;

    public BruteForceRule(int threshold, int windowMinutes) {
        this.threshold = threshold;
        this.windowMinutes = windowMinutes;
    }

    @Override
    public String getName() {
        return "Brute Force Login Failures";
    }

    @Override
    public Optional<Alert> match(LogEntry entry, RuleContext context) {
        if (!entry.isLoginFailure()) {
            return Optional.empty();
        }

        String ip = entry.getIp();
        if (ip == null || ip.trim().isEmpty()) {
            return Optional.empty();
        }

        Map<String, ArrayDeque<LocalDateTime>> map = context.getFailuresByIp();
        ArrayDeque<LocalDateTime> deque = map.computeIfAbsent(ip, k -> new ArrayDeque<>());

        LocalDateTime now = entry.getTimestamp();
        deque.addLast(now);

        while (!deque.isEmpty() && deque.peekFirst().isBefore(now.minusMinutes(windowMinutes))) {
            deque.removeFirst();
        }

        // Alert once when it hits threshold
        if (deque.size() == threshold) {
            String desc = "Detected " + threshold + " failed logins within " + windowMinutes
                    + " minutes from ip=" + ip;
            return Optional.of(new Alert(getName(), Severity.HIGH, desc, entry));
        }

        return Optional.empty();
    }
}
