package burp.jsendpointfinder;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
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
    private final JPanel mainPanel;

    private volatile Pattern customExcludePattern;
    private final Set<String> globalDedup;

    public EndpointTab(MontoyaApi api, Set<String> globalDedup) {
        this.api = api;
        this.globalDedup = globalDedup;
        this.tableModel = new EndpointTableModel();

        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(250);
        table.getColumnModel().getColumn(2).setPreferredWidth(250);
        table.getColumnModel().getColumn(3).setPreferredWidth(300);

        this.searchField = new JTextField();
        this.excludeField = new JTextField();
        this.scopeCheckbox = new JCheckBox("In-scope only", true);
        this.statusLabel = new JLabel("Total unique endpoints: 0");

        this.mainPanel = buildPanel();

        searchField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applySearchFilter));
        excludeField.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyExcludePattern));
    }

    private JPanel buildPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 4, 2, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

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

        copyAllBtn.addActionListener(e -> copyAll());
        copySelectedBtn.addActionListener(e -> copySelected());
        exportTxtBtn.addActionListener(e -> exportTxt());
        exportJsonBtn.addActionListener(e -> exportJson());
        clearBtn.addActionListener(e -> clearAll());

        buttonPanel.add(copyAllBtn);
        buttonPanel.add(copySelectedBtn);
        buttonPanel.add(exportTxtBtn);
        buttonPanel.add(exportJsonBtn);
        buttonPanel.add(clearBtn);

        bottomPanel.add(buttonPanel, BorderLayout.WEST);
        bottomPanel.add(statusLabel, BorderLayout.EAST);

        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
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

    public void addRecord(EndpointRecord record) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRecord(record);
            statusLabel.setText("Total unique endpoints: " + tableModel.getRowCount());
        });
    }

    private void applySearchFilter() {
        String text = searchField.getText();
        if (text == null || text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            try {
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text), 1));
            } catch (PatternSyntaxException ignored) {
                sorter.setRowFilter(null);
            }
        }
    }

    private void applyExcludePattern() {
        String text = excludeField.getText();
        if (text == null || text.isEmpty()) {
            customExcludePattern = null;
            excludeField.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextField.border"));
            return;
        }
        try {
            customExcludePattern = Pattern.compile(text);
            excludeField.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextField.border"));
        } catch (PatternSyntaxException e) {
            customExcludePattern = null;
            excludeField.setBorder(new LineBorder(Color.RED, 2));
        }
    }

    private List<String> getVisibleEndpoints() {
        List<String> endpoints = new ArrayList<>();
        for (int viewRow = 0; viewRow < table.getRowCount(); viewRow++) {
            Object val = table.getValueAt(viewRow, 1);
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
            Object endpoint = table.getValueAt(viewRow, 1);
            Object source = table.getValueAt(viewRow, 2);
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

    private void clearAll() {
        int result = JOptionPane.showConfirmDialog(
                mainPanel,
                "Clear all endpoints and reset deduplication?",
                "JS Endpoint Finder",
                JOptionPane.YES_NO_OPTION
        );
        if (result == JOptionPane.YES_OPTION) {
            globalDedup.clear();
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
