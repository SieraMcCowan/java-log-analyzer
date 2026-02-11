package loganalyzer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IpRiskScorer {

    public static Map<String, Integer> scoreByIp(List<Alert> alerts) {
        Map<String, Integer> scores = new HashMap<>();

        for (Alert a : alerts) {
            if (a == null || a.getEntry() == null) continue;

            String ip = a.getEntry().getIp();
            if (ip == null || ip.isBlank()) continue;

            int points = severityPoints(a.getSeverity());
            scores.put(ip, scores.getOrDefault(ip, 0) + points);
        }

        return scores;
    }

    private static int severityPoints(Severity s) {
        if (s == Severity.HIGH) return 3;
        if (s == Severity.MEDIUM) return 2;
        return 1;
    }
}
