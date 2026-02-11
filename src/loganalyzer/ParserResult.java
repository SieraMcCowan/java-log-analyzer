package loganalyzer;

import java.util.List;

public class ParserResult {
    private final java.util.List<LogEntry> entries;
    private final ParserStats stats;

    public ParserResult(List<LogEntry> entries, ParserStats stats) {
        this.entries = entries;
        this.stats = stats;
    }

    public List<LogEntry> getEntries() { return entries; }
    public ParserStats getStats() { return stats; }
}
