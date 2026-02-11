package loganalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AnalysisResult {

    private final List<Alert> alerts = new ArrayList<>();
    private Map<String, Integer> ipScores = new HashMap<>();

    public void addAlert(Alert alert) {
        if (alert != null) alerts.add(alert);
    }

    public List<Alert> getAlerts() {
        return Collections.unmodifiableList(alerts);
    }

    public void computeIpScores() {
        this.ipScores = IpRiskScorer.scoreByIp(alerts);
    }

    public Map<String, Integer> getIpScores() {
        return Collections.unmodifiableMap(ipScores);
    }
}
