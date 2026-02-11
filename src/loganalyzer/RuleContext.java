package loganalyzer;

import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;

public class RuleContext {

    // Recent login failures per IP
    private final Map<String, ArrayDeque<LocalDateTime>> failuresByIp = new HashMap<>();

    public Map<String, ArrayDeque<LocalDateTime>> getFailuresByIp() {
        return failuresByIp;
    }
}
