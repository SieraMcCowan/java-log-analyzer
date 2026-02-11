package loganalyzer;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class CsvExporter {

    public static void exportAlerts(Path outputPath, List<Alert> alerts) throws Exception {
        try (BufferedWriter bw = Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8)) {
            bw.write("timestamp,severity,rule,ip,user,description,rawLine");
            bw.newLine();

            for (Alert a : alerts) {
                LogEntry e = a.getEntry();

                String ts = safe(e.getTimestamp().toString());
                String sev = safe(a.getSeverity().name());
                String rule = safe(a.getRuleName());
                String ip = safe(e.getIp());
                String user = safe(e.getUser());
                String desc = safe(a.getDescription());
                String raw = safe(e.getRawLine());

                bw.write(csv(ts) + "," + csv(sev) + "," + csv(rule) + "," + csv(ip) + ","
                        + csv(user) + "," + csv(desc) + "," + csv(raw));
                bw.newLine();
            }
        }
    }

    private static String safe(String s) {
        return (s == null) ? "" : s;
    }

    private static String csv(String s) {
        String cleaned = s.replace("\"", "\"\"");
        return "\"" + cleaned + "\"";
    }
}
