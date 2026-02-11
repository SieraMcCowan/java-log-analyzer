# Java Log Analyzer (Rule-Based Detection Engine)

A Java-based log analysis tool built in Apache NetBeans that detects suspicious activity using rule-based security logic.  

This project simulates basic SIEM-style functionality including parsing, detection rules, severity classification, risk scoring, and CSV export.

---

## Features

### Supported Log Formats
- Structured application logs  
- Linux SSH authentication logs (/var/log/auth.log style)

### Detection Rules

**HIGH Severity**
- Admin/Root account targeting
- Brute force login detection (5 failed attempts within 5 minutes)

**MEDIUM Severity**
- Off-hours successful login detection (12:00 AM – 4:59 AM)

**LOW Severity**
- Single failed login attempt (non-privileged accounts)

### Additional Capabilities
- Top suspicious IP ranking based on severity score
- GUI-based file selection and analysis
- Severity filtering (ALL, LOW, MEDIUM, HIGH)
- Color-coded alert table
- CSV export of alerts
- Summary statistics view

---

## Architecture

The application uses a modular design:

- `ILogParser` interface for multi-format log parsing
- Rule engine using `DetectionRule` interface
- Severity-based alert classification
- IP risk scoring model
- Swing-based GUI interface

This separation allows new log formats and detection rules to be added easily.

---

## Example Detection Output

```
[HIGH] Admin/Root Targeting | Failed login attempt for privileged account user=admin from ip=10.0.0.5
[HIGH] Brute Force Login Failures | Detected 5 failed logins within 5 minutes from ip=10.0.0.5
[MEDIUM] Off-Hours Login | Login success during off-hours user=siera ip=10.0.0.8
[LOW] Single Failed Login | Single failed login user=bob ip=10.0.0.22
```

---

## Technologies Used

- Java
- Apache NetBeans (Ant build)
- Java Swing (GUI)
- Regex parsing
- Object-oriented rule engine design

---

## How to Run

1. Open the project in Apache NetBeans  
2. Build the project  
3. Run the application  
4. Select log format (STRUCTURED or AUTH)  
5. Load a log file  
6. Click Analyze  

---

## Future Improvements

- Configurable detection thresholds
- Real-time log streaming support
- Additional log formats (web server logs, Windows event logs)
- PDF summary export
- Drag-and-drop file support

---

## Author

Siera McCowan  
B.S. Computer Information Systems (Cybersecurity Focus)  
Austin Peay State University
