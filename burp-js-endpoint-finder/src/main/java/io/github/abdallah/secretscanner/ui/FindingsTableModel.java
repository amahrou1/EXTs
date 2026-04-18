package io.github.abdallah.secretscanner.ui;

import io.github.abdallah.secretscanner.model.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public final class FindingsTableModel extends AbstractTableModel {

    static final int COL_TIME      = 0;
    static final int COL_RULE      = 1;
    static final int COL_SEVERITY  = 2;
    static final int COL_HOST      = 3;
    static final int COL_URL       = 4;
    static final int COL_MATCH     = 5;
    static final int COL_ENTROPY   = 6;
    static final int COL_VALIDATED = 7;

    private static final String[] COLUMNS = {
            "Time", "Rule", "Sev", "Host", "URL", "Match", "Entropy", "Validated"
    };

    private static final int MAX_ROWS = 10_000;

    private final List<Finding> rows = new ArrayList<>();
    private boolean capped = false;

    @Override public int getRowCount()    { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        if (row < 0 || row >= rows.size()) return null;
        Finding f = rows.get(row);
        return switch (col) {
            case COL_TIME      -> f.timestampFormatted();
            case COL_RULE      -> f.rule().name();
            case COL_SEVERITY  -> f.effectiveSeverity().name();
            case COL_HOST      -> f.host();
            case COL_URL       -> f.url();
            case COL_MATCH     -> f.matchTruncated();
            case COL_ENTROPY   -> String.format("%.2f", f.entropy());
            case COL_VALIDATED -> validatedLabel(f);
            default            -> null;
        };
    }

    private String validatedLabel(Finding f) {
        if (f.isPendingValidation()) return "Validating\u2026";
        return switch (f.validationResult()) {
            case VALID           -> "\u2713 VALID";
            case INVALID         -> "\u2717 INVALID";
            case RATE_LIMITED    -> "Rate-limited";
            case NETWORK_ERROR   -> "Net error";
            case NOT_IMPLEMENTED -> "N/A";
            default              -> "";
        };
    }

    public boolean addFinding(Finding f) {
        if (rows.size() >= MAX_ROWS) {
            capped = true;
            rows.remove(0);
            fireTableRowsDeleted(0, 0);
        }
        rows.add(f);
        int idx = rows.size() - 1;
        fireTableRowsInserted(idx, idx);
        return !capped;
    }

    public Finding getRow(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow);
    }

    public List<Finding> getAllFindings() {
        return List.copyOf(rows);
    }

    public boolean isCapped() { return capped; }

    public void clear() {
        rows.clear();
        capped = false;
        fireTableDataChanged();
    }

    public void refreshRow(Finding f) {
        int idx = rows.indexOf(f);
        if (idx >= 0) fireTableRowsUpdated(idx, idx);
    }

    public void removeFinding(Finding f) {
        int idx = rows.indexOf(f);
        if (idx >= 0) {
            rows.remove(idx);
            fireTableRowsDeleted(idx, idx);
        }
    }

    public void removeFindings(List<Finding> findings) {
        for (Finding f : findings) removeFinding(f);
    }
}
