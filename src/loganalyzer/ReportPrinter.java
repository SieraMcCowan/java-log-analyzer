package loganalyzer;

import java.util.Map;
import java.util.stream.Collectors;

public class ReportPrinter {

    public static String buildSummaryText(ParserStats stats, java.util.List<LogEntry> entries, AnalysisResult result) {
        StringBuilder sb = new StringBuilder();

        sb.append("=== Log Analyzer Summary ===\n");
        sb.append("Total lines read: ").append(stats.totalLines).append("\n");
        sb.append("Parsed entries:   ").append(stats.parsedLines).append("\n");
        sb.append("Skipped lines:    ").append(stats.skippedLines).append("\n");
        sb.append("Alerts found:     ").append(result.getAlerts().size()).append("\n\n");

        Map<Severity, Long> counts = result.getAlerts().stream()
                .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));

        sb.append("Alerts by severity:\n");
        for (Severity s : Severity.values()) {
            sb.append("  ").append(s).append(": ").append(counts.getOrDefault(s, 0L)).append("\n");
        }

        sb.append("\nTop suspicious IPs:\n");
        java.util.List<Map.Entry<String, Integer>> topIps = result.getIpScores().entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(10)
                .collect(Collectors.toList());

        if (topIps.isEmpty()) {
            sb.append("  (none)\n");
        } else {
            for (Map.Entry<String, Integer> e : topIps) {
                sb.append("  ").append(e.getKey()).append(" -> score ").append(e.getValue()).append("\n");
            }
        }

        sb.append("\nTop alerts (up to 10):\n");
        int limit = Math.min(10, result.getAlerts().size());
        for (int i = 0; i < limit; i++) {
            Alert a = result.getAlerts().get(i);
            sb.append("- [").append(a.getSeverity()).append("] ")
              .append(a.getRuleName()).append(" | ")
              .append(a.getDescription()).append("\n");
        }

        return sb.toString();
    }
}
