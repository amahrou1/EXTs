package burp.jsendpointfinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class EndpointTab {

    private final MontoyaApi api;
    private final EndpointTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<EndpointTableModel> sorter;
    private final JLabel statusLabel;
    private final JTextField searchField;
    private final JTextField excludeField;
    private final JCheckBox scopeCheckbox;
    private final JCheckBox hideSeenCheckbox;
    private final Map<EndpointType, JCheckBox> typeCheckboxes = new EnumMap<>(EndpointType.class);
    private final JPanel mainPanel;

    private final ExecutorService executor;
    private final EndpointStore store;
    private volatile Runnable saveTrigger;

    private volatile Pattern customExcludePattern;
    private final Set<String> globalDedup;

    public EndpointTab(MontoyaApi api, Set<String> globalDedup, ExecutorService executor, EndpointStore store) {
        this.api = api;
        this.globalDedup = globalDedup;
        this.executor = executor;
        this.store = store;
        this.tableModel = new EndpointTableModel();

        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(EndpointTableModel.COL_INDEX).setMaxWidth(60);
        table.getColumnModel().getColumn(EndpointTableModel.COL_INDEX).setPreferredWidth(40);
        table.getColumnModel().getColumn(EndpointTableModel.COL_ENDPOINT).setPreferredWidth(250);
        table.getColumnModel().getColumn(EndpointTableModel.COL_SOURCE).setPreferredWidth(250);
        table.getColumnModel().getColumn(EndpointTableModel.COL_TYPE).setPreferredWidth(80);
        table.getColumnModel().getColumn(EndpointTableModel.COL_TYPE).setMaxWidth(120);
        table.getColumnModel().getColumn(EndpointTableModel.COL_CONTEXT).setPreferredWidth(300);

        this.searchField = new JTextField();
        this.excludeField = new JTextField();
        this.scopeCheckbox = new JCheckBox("In-scope only", true);
        this.hideSeenCheckbox = new JCheckBox("Hide seen", false);
        for (EndpointType t : EndpointType.values()) {
            boolean defaultChecked = t != EndpointType.FRONTEND_ROUTE;
            typeCheckboxes.put(t, new JCheckBox(t.name(), defaultChecked));
        }
        this.statusLabel = new JLabel("Total unique endpoints: 0");

        this.mainPanel = buildPanel();
        attachTablePopup();

        searchField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyFilters));
        excludeField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyExcludePattern));
        hideSeenCheckbox.addActionListener(e -> applyFilters());
        for (JCheckBox cb : typeCheckboxes.values()) {
            cb.addActionListener(e -> applyFilters());
        }
    }

    private JPanel buildPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Search + Exclude + In-scope
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        topPanel.add(new JLabel("Search:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        topPanel.add(searchField, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        topPanel.add(new JLabel("Custom exclude regex:"), gbc);
        gbc.gridx = 3; gbc.weightx = 0.5;
        topPanel.add(excludeField, gbc);

        gbc.gridx = 4; gbc.weightx = 0;
        topPanel.add(scopeCheckbox, gbc);

        // Row 1: Type filters
        JPanel typePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        typePanel.add(new JLabel("Types:"));
        for (EndpointType t : EndpointType.values()) {
            typePanel.add(typeCheckboxes.get(t));
        }
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        gbc.gridwidth = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        topPanel.add(typePanel, gbc);
        gbc.gridwidth = 1;

        panel.add(topPanel, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton copyAllBtn = new JButton("Copy All");
        JButton copySelectedBtn = new JButton("Copy Selected");
        JButton exportTxtBtn = new JButton("Export TXT");
        JButton exportJsonBtn = new JButton("Export JSON");
        JButton clearBtn = new JButton("Clear");
        JButton markAllSeenBtn = new JButton("Mark all seen");

        copyAllBtn.addActionListener(e -> copyAll());
        copySelectedBtn.addActionListener(e -> copySelected());
        exportTxtBtn.addActionListener(e -> exportTxt());
        exportJsonBtn.addActionListener(e -> exportJson());
        clearBtn.addActionListener(e -> clearAll());
        markAllSeenBtn.addActionListener(e -> markAllSeen());

        buttonPanel.add(copyAllBtn);
        buttonPanel.add(copySelectedBtn);
        buttonPanel.add(exportTxtBtn);
        buttonPanel.add(exportJsonBtn);
        buttonPanel.add(clearBtn);
        buttonPanel.add(markAllSeenBtn);
        buttonPanel.add(hideSeenCheckbox);

        bottomPanel.add(buttonPanel, BorderLayout.WEST);
        bottomPanel.add(statusLabel, BorderLayout.EAST);

        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void attachTablePopup() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem getItem = new JMenuItem("Send to Repeater (GET)");
        JMenuItem postItem = new JMenuItem("Send to Repeater (POST)");
        getItem.addActionListener(e -> sendSelectedToRepeater("GET"));
        postItem.addActionListener(e -> sendSelectedToRepeater("POST"));
        popup.add(getItem);
        popup.add(postItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShow(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShow(e);
            }

            private void maybeShow(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row);
                }
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    public EndpointTableModel getTableModel() {
        return tableModel;
    }

    public boolean isScopeOnly() {
        return scopeCheckbox.isSelected();
    }

    public Pattern getCustomExcludePattern() {
        return customExcludePattern;
    }

    public void setSaveTrigger(Runnable saveTrigger) {
        this.saveTrigger = saveTrigger;
    }

    public void addRecord(EndpointRecord record) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRecord(record);
            statusLabel.setText("Total unique endpoints: " + tableModel.getRowCount());
            fireSaveTrigger();
        });
    }

    public void loadRecords(List<EndpointRecord> records) {
        if (records == null || records.isEmpty()) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            for (EndpointRecord r : records) {
                tableModel.addRecord(r);
            }
            statusLabel.setText("Total unique endpoints: " + tableModel.getRowCount());
        });
    }

    private void fireSaveTrigger() {
        Runnable r = saveTrigger;
        if (r != null) {
            try {
                r.run();
            } catch (Throwable ignored) {
            }
        }
    }

    private void applyFilters() {
        String searchText = searchField.getText();
        RowFilter<EndpointTableModel, Integer> searchFilter = null;
        if (searchText != null && !searchText.isEmpty()) {
            try {
                searchFilter = RowFilter.regexFilter("(?i)" + searchText, EndpointTableModel.COL_ENDPOINT);
                searchField.setBorder(defaultTextFieldBorder());
            } catch (PatternSyntaxException e) {
                searchField.setBorder(new LineBorder(Color.RED, 2));
                sorter.setRowFilter(buildCombinedFilter(null));
                return;
            }
        } else {
            searchField.setBorder(defaultTextFieldBorder());
        }

        sorter.setRowFilter(buildCombinedFilter(searchFilter));
    }

    private RowFilter<EndpointTableModel, Integer> buildCombinedFilter(
            RowFilter<EndpointTableModel, Integer> searchFilter) {
        List<RowFilter<EndpointTableModel, Integer>> filters = new ArrayList<>();
        if (searchFilter != null) {
            filters.add(searchFilter);
        }
        if (hideSeenCheckbox.isSelected()) {
            filters.add(new RowFilter<EndpointTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends EndpointTableModel, ? extends Integer> entry) {
                    EndpointRecord rec = entry.getModel().getRecord(entry.getIdentifier());
                    return !rec.seen();
                }
            });
        }
        filters.add(new RowFilter<EndpointTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends EndpointTableModel, ? extends Integer> entry) {
                EndpointRecord rec = entry.getModel().getRecord(entry.getIdentifier());
                JCheckBox cb = typeCheckboxes.get(rec.type());
                return cb == null || cb.isSelected();
            }
        });
        if (filters.isEmpty()) {
            return null;
        }
        if (filters.size() == 1) {
            return filters.get(0);
        }
        return RowFilter.andFilter(filters);
    }

    private Border defaultTextFieldBorder() {
        Border b = UIManager.getLookAndFeel().getDefaults().getBorder("TextField.border");
        return b != null ? b : BorderFactory.createLineBorder(Color.GRAY);
    }

    private void applyExcludePattern() {
        String text = excludeField.getText();
        if (text == null || text.isEmpty()) {
            customExcludePattern = null;
            excludeField.setBorder(defaultTextFieldBorder());
            return;
        }
        try {
            customExcludePattern = Pattern.compile(text);
            excludeField.setBorder(defaultTextFieldBorder());
        } catch (PatternSyntaxException e) {
            customExcludePattern = null;
            excludeField.setBorder(new LineBorder(Color.RED, 2));
        }
    }

    private List<String> getVisibleEndpoints() {
        List<String> endpoints = new ArrayList<>();
        for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
            Object val = table.getValueAt(viewRow, EndpointTableModel.COL_ENDPOINT);
            if (val != null) {
                endpoints.add(val.toString());
            }
        }
        return endpoints;
    }

    private List<EndpointRecord> getVisibleRecords() {
        List<EndpointRecord> records = new ArrayList<>();
        for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            records.add(tableModel.getRecord(modelRow));
        }
        return records;
    }

    private List<EndpointRecord> getSelectedRecords() {
        int[] selectedRows = table.getSelectedRows();
        List<EndpointRecord> out = new ArrayList<>();
        for (int viewRow : selectedRows) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            out.add(tableModel.getRecord(modelRow));
        }
        return out;
    }

    private void copyAll() {
        List<String> endpoints = getVisibleEndpoints();
        if (endpoints.isEmpty()) {
            return;
        }
        String text = String.join("\n", endpoints);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    private void copySelected() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (int viewRow : selectedRows) {
            Object endpoint = table.getValueAt(viewRow, EndpointTableModel.COL_ENDPOINT);
            Object source = table.getValueAt(viewRow, EndpointTableModel.COL_SOURCE);
            if (endpoint != null) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(endpoint);
                sb.append('\t');
                sb.append(source != null ? source.toString() : "");
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
    }

    private void exportTxt() {
        List<String> endpoints = getVisibleEndpoints();
        if (endpoints.isEmpty()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("js_endpoints.txt"));
        if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(chooser.getSelectedFile(), StandardCharsets.UTF_8)) {
                for (String ep : endpoints) {
                    fw.write(ep);
                    fw.write('\n');
                }
            } catch (IOException ex) {
                api.logging().logToError("Export TXT failed: " + ex.getMessage());
            }
        }
    }

    private void exportJson() {
        List<EndpointRecord> records = getVisibleRecords();
        if (records.isEmpty()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("js_endpoints.json"));
        if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(chooser.getSelectedFile(), StandardCharsets.UTF_8)) {
                fw.write(JsonExporter.toJson(records));
            } catch (IOException ex) {
                api.logging().logToError("Export JSON failed: " + ex.getMessage());
            }
        }
    }

    private void markAllSeen() {
        tableModel.markAllSeen();
        fireSaveTrigger();
        applyFilters();
    }

    private void sendSelectedToRepeater(String method) {
        List<EndpointRecord> selected = getSelectedRecords();
        if (selected.isEmpty()) {
            return;
        }
        executor.submit(() -> {
            for (EndpointRecord rec : selected) {
                try {
                    String absolute = UrlResolver.toAbsolute(rec.endpoint(), rec.sourceUrl());
                    if (absolute == null || absolute.isEmpty()
                            || !(absolute.startsWith("http://") || absolute.startsWith("https://"))) {
                        api.logging().logToError(
                                "Send to Repeater: could not resolve '" + rec.endpoint()
                                        + "' against '" + rec.sourceUrl() + "'");
                        continue;
                    }
                    HttpRequest req = HttpRequest.httpRequestFromUrl(absolute);
                    if ("POST".equals(method)) {
                        req = req.withMethod("POST").withBody("");
                    }
                    String ep = rec.endpoint();
                    String tabName = "JSF: " + ep.substring(0, Math.min(40, ep.length()));
                    api.repeater().sendToRepeater(req, tabName);
                } catch (Throwable t) {
                    api.logging().logToError(
                            "Send to Repeater failed for " + rec.endpoint() + ": " + t.getMessage());
                }
            }
        });
    }

    private void clearAll() {
        int result = JOptionPane.showConfirmDialog(
                mainPanel,
                "Clear all endpoints, seen state, and persisted file?",
                "JS Endpoint Finder",
                JOptionPane.YES_NO_OPTION
        );
        if (result == JOptionPane.YES_OPTION) {
            globalDedup.clear();
            if (store != null) {
                store.deleteFile();
            }
            SwingUtilities.invokeLater(() -> {
                tableModel.clear();
                statusLabel.setText("Total unique endpoints: 0");
            });
        }
    }

    private static class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable action;

        SimpleDocumentListener(Runnable action) {
            this.action = action;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            action.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            action.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            action.run();
        }
    }
}
