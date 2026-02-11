package loganalyzer;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structured format:
 * 2026-02-11 08:45:10 WARN Login failed user=admin ip=10.0.0.5
 */
public class StructuredLogParser implements ILogParser {

    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2})\\s+(\\d{2}:\\d{2}:\\d{2})\\s+(INFO|WARN|ERROR)\\s+(\\w+)\\s+(\\w+)(?:\\s+user=([^\\s]+))?(?:\\s+ip=([^\\s]+))?.*$"
    );

    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public ParserResult parse(Path filePath) throws Exception {
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("File does not exist: " + filePath);
        }

        ParserStats stats = new ParserStats();
        List<LogEntry> entries = new ArrayList<>();

        try (BufferedReader br = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                stats.totalLines++;

                LogEntry entry = parseLine(line);
                if (entry != null) {
                    entries.add(entry);
                    stats.parsedLines++;
                } else {
                    stats.skippedLines++;
                }
            }
        }

        return new ParserResult(entries, stats);
    }

    private LogEntry parseLine(String line) {
        Matcher m = LOG_PATTERN.matcher(line);
        if (!m.matches()) return null;

        String date = m.group(1);
        String time = m.group(2);
        String level = m.group(3);
        String action = m.group(4);
        String outcome = m.group(5);
        String user = m.group(6);
        String ip = m.group(7);

        LocalDateTime ts = LocalDateTime.parse(date + " " + time, TS_FORMAT);

        return new LogEntry(ts, level, action, outcome, user, ip, line, LogFormat.STRUCTURED);
    }

    @Override
    public LogFormat getFormat() {
        return LogFormat.STRUCTURED;
    }
}
