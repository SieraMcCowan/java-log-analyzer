package loganalyzer;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.Year;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Common Linux /var/log/auth.log SSH lines:
 * Feb 11 08:41:00 host sshd[123]: Failed password for invalid user admin from 10.0.0.5 port 51234 ssh2
 * Feb 11 08:42:10 host sshd[124]: Accepted password for siera from 10.0.0.8 port 54421 ssh2
 *
 * auth.log usually has no year, so we assume the current year.
 */
public class AuthLogParser implements ILogParser {

    private static final Pattern FAILED = Pattern.compile(
            "^(\\w{3})\\s+(\\d{1,2})\\s+(\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd\\[\\d+\\]:\\s+Failed password for (?:invalid user\\s+)?(\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+).*$"
    );

    private static final Pattern ACCEPTED = Pattern.compile(
            "^(\\w{3})\\s+(\\d{1,2})\\s+(\\d{2}:\\d{2}:\\d{2})\\s+\\S+\\s+sshd\\[\\d+\\]:\\s+Accepted \\S+ for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+).*$"
    );

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);

    @Override
    public ParserResult parse(Path filePath) throws Exception {
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("File does not exist: " + filePath);
        }

        ParserStats stats = new ParserStats();
        List<LogEntry> entries = new ArrayList<>();
        int year = Year.now().getValue();

        try (BufferedReader br = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                stats.totalLines++;

                LogEntry entry = parseLine(line, year);
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

    private LogEntry parseLine(String line, int year) {
        Matcher mFail = FAILED.matcher(line);
        if (mFail.matches()) {
            LocalDateTime ts = parseTs(year, mFail.group(1), mFail.group(2), mFail.group(3));
            String user = mFail.group(4);
            String ip = mFail.group(5);

            return new LogEntry(ts, "WARN", "Login", "failed", user, ip, line, LogFormat.AUTH);
        }

        Matcher mAcc = ACCEPTED.matcher(line);
        if (mAcc.matches()) {
            LocalDateTime ts = parseTs(year, mAcc.group(1), mAcc.group(2), mAcc.group(3));
            String user = mAcc.group(4);
            String ip = mAcc.group(5);

            return new LogEntry(ts, "INFO", "Login", "success", user, ip, line, LogFormat.AUTH);
        }

        return null;
    }

    private LocalDateTime parseTs(int year, String mon, String day, String time) {
        String input = year + " " + mon + " " + day + " " + time;
        return LocalDateTime.parse(input, TS);
    }

    @Override
    public LogFormat getFormat() {
        return LogFormat.AUTH;
    }
}
