package loganalyzer;

import java.nio.file.Path;

public interface ILogParser {
    ParserResult parse(Path filePath) throws Exception;
    LogFormat getFormat();
}
