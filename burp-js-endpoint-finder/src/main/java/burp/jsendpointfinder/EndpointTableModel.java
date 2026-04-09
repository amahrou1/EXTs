package burp.jsendpointfinder;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class EndpointTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Endpoint", "Source URL", "Status", "Found At", "Context"};

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
        if (columnIndex == 0) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        EndpointRecord rec = records.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> rowIndex + 1;
            case 1 -> rec.endpoint();
            case 2 -> rec.sourceUrl();
            case 3 -> rec.status();
            case 4 -> rec.foundAtFormatted();
            case 5 -> rec.context();
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

    public void clear() {
        int size = records.size();
        if (size > 0) {
            records.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }
}
