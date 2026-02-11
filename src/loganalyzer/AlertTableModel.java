package loganalyzer;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

public class AlertTableModel extends AbstractTableModel {

    private final String[] columns = {"Timestamp", "Severity", "Rule", "IP", "User", "Description"};
    private List<Alert> rows = new ArrayList<>();

    public void setAlerts(List<Alert> alerts) {
        this.rows = (alerts == null) ? new ArrayList<>() : new ArrayList<>(alerts);
        fireTableDataChanged();
    }

    public Alert getAlertAt(int row) {
        if (row < 0 || row >= rows.size()) return null;
        return rows.get(row);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int col) {
        return columns[col];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Alert a = rows.get(rowIndex);
        LogEntry e = a.getEntry();

        switch (columnIndex) {
            case 0: return e.getTimestamp();
            case 1: return a.getSeverity();
            case 2: return a.getRuleName();
            case 3: return e.getIp();
            case 4: return e.getUser();
            case 5: return a.getDescription();
            default: return "";
        }
    }
}
