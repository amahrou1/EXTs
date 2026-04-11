package burp.jsendpointfinder;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class EndpointTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Endpoint", "Source URL", "Type", "Context"};

    public static final int COL_INDEX = 0;
    public static final int COL_ENDPOINT = 1;
    public static final int COL_SOURCE = 2;
    public static final int COL_TYPE = 3;
    public static final int COL_CONTEXT = 4;

    private final List<EndpointRecord> records = new ArrayList<>();

    @Override
    public int getRowCount() {
        return records.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == COL_INDEX) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        EndpointRecord rec = records.get(rowIndex);
        return switch (columnIndex) {
            case COL_INDEX -> rowIndex + 1;
            case COL_ENDPOINT -> rec.endpoint();
            case COL_SOURCE -> rec.sourceUrl();
            case COL_TYPE -> rec.type().name();
            case COL_CONTEXT -> rec.context();
            default -> "";
        };
    }

    public void addRecord(EndpointRecord record) {
        int idx = records.size();
        records.add(record);
        fireTableRowsInserted(idx, idx);
    }

    public EndpointRecord getRecord(int rowIndex) {
        return records.get(rowIndex);
    }

    public List<EndpointRecord> getAllRecords() {
        return new ArrayList<>(records);
    }

    public void markAllSeen() {
        if (records.isEmpty()) {
            return;
        }
        for (EndpointRecord r : records) {
            r.markSeen();
        }
        fireTableRowsUpdated(0, records.size() - 1);
    }

    public void clear() {
        int size = records.size();
        if (size > 0) {
            records.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }
}
