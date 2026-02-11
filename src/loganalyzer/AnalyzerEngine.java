package loganalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class AnalyzerEngine {

    private final List<DetectionRule> rules = new ArrayList<>();

    public void addRule(DetectionRule rule) {
        if (rule != null) rules.add(rule);
    }

    public AnalysisResult analyze(List<LogEntry> entries) {
        RuleContext context = new RuleContext();
        AnalysisResult result = new AnalysisResult();

        for (LogEntry entry : entries) {
            for (DetectionRule rule : rules) {
                Optional<Alert> alertOpt = rule.match(entry, context);
                alertOpt.ifPresent(result::addAlert);
            }
        }

        result.computeIpScores();
        return result;
    }
}
