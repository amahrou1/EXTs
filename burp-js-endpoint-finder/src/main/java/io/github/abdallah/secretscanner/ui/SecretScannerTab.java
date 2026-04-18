package io.github.abdallah.secretscanner.ui;

import io.github.abdallah.secretscanner.engine.Rule;
import io.github.abdallah.secretscanner.engine.RuleLoader;
import io.github.abdallah.secretscanner.engine.SecretScanner;
import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.validator.ValidatorRegistry;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SecretScannerTab {

    private final JPanel panel;
    private final FindingsTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<FindingsTableModel> sorter;
    private final DetailPane detailPane;
    private final JCheckBox autoScanCheckbox;
    private final JLabel statusLabel;
    private final JLabel capWarning;
    private final SecretScanner scanner;
    private final ScheduledExecutorService executor;

    private final AtomicBoolean autoScan = new AtomicBoolean(false);

    public SecretScannerTab(SecretScanner scanner, ValidatorRegistry validators,
                            ScheduledExecutorService executor) {
        this.scanner = scanner;
        this.executor = executor;
        this.tableModel = new FindingsTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        this.detailPane = new DetailPane(validators, executor, (f, tm) -> {
            // callback after validation — nothing extra to do here
        });
        detailPane.setTableModel(tableModel);

        this.autoScanCheckbox = new JCheckBox("Auto-scan all responses", false);
        this.statusLabel = new JLabel("Rules: " + scanner.ruleCount() + "   Findings: 0");
        this.capWarning = new JLabel("");
        capWarning.setForeground(Color.RED);

        autoScanCheckbox.addActionListener(e -> autoScan.set(autoScanCheckbox.isSelected()));

        configureTable();
        this.panel = buildPanel();
        attachPopup();
    }

    private void configureTable() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(FindingsTableModel.COL_TIME).setPreferredWidth(140);
        table.getColumnModel().getColumn(FindingsTableModel.COL_RULE).setPreferredWidth(200);
        table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY).setPreferredWidth(70);
        table.getColumnModel().getColumn(FindingsTableModel.COL_HOST).setPreferredWidth(150);
        table.getColumnModel().getColumn(FindingsTableModel.COL_URL).setPreferredWidth(200);
        table.getColumnModel().getColumn(FindingsTableModel.COL_MATCH).setPreferredWidth(180);
        table.getColumnModel().getColumn(FindingsTableModel.COL_ENTROPY).setPreferredWidth(60);
        table.getColumnModel().getColumn(FindingsTableModel.COL_VALIDATED).setPreferredWidth(90);

        // Severity column color
        table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY)
                .setCellRenderer(new SeverityRenderer());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) { detailPane.show(null); return; }
            int modelRow = table.convertRowIndexToModel(viewRow);
            detailPane.show(tableModel.getRow(modelRow));
        });
    }

    private JPanel buildPanel() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Toolbar row
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        toolbar.add(autoScanCheckbox);

        JButton loadRulesBtn = new JButton("Load rules…");
        loadRulesBtn.addActionListener(e -> loadRulesFromFile());
        toolbar.add(loadRulesBtn);

        JButton clearBtn = new JButton("Clear findings");
        clearBtn.addActionListener(e -> clearFindings());
        toolbar.add(clearBtn);

        JButton exportBtn = new JButton("Export JSON");
        exportBtn.addActionListener(e -> exportJson());
        toolbar.add(exportBtn);

        toolbar.add(statusLabel);
        toolbar.add(capWarning);

        // Split: table on top, detail on bottom
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), detailPane);
        split.setDividerLocation(300);
        split.setResizeWeight(0.65);

        p.add(toolbar, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void attachPopup() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyMatch = new JMenuItem("Copy match");
        JMenuItem copyAll   = new JMenuItem("Copy all visible findings");
        copyMatch.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                int modelRow = table.convertRowIndexToModel(row);
                Finding f = tableModel.getRow(modelRow);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(f.match()), null);
            }
        });
        copyAll.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < table.getRowCount(); i++) {
                int mi = table.convertRowIndexToModel(i);
                Finding f = tableModel.getRow(mi);
                if (sb.length() > 0) sb.append('\n');
                sb.append(f.rule().id()).append('\t').append(f.host())
                  .append('\t').append(f.match());
            }
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        });
        popup.add(copyMatch);
        popup.add(copyAll);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            private void show(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row))
                    table.setRowSelectionInterval(row, row);
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
            @Override public void mousePressed(java.awt.event.MouseEvent e)  { show(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { show(e); }
        });
    }

    public JPanel getPanel() { return panel; }

    public boolean isAutoScanEnabled() { return autoScan.get(); }

    public void addFinding(Finding f) {
        SwingUtilities.invokeLater(() -> {
            boolean ok = tableModel.addFinding(f);
            if (!ok) capWarning.setText("⚠ Cap reached: oldest findings dropped");
            statusLabel.setText("Rules: " + scanner.ruleCount()
                    + "   Findings: " + tableModel.getRowCount());
        });
    }

    private void clearFindings() {
        int res = JOptionPane.showConfirmDialog(panel,
                "Clear all findings?", "Secret Scanner", JOptionPane.YES_NO_OPTION);
        if (res == JOptionPane.YES_OPTION) {
            tableModel.clear();
            capWarning.setText("");
            statusLabel.setText("Rules: " + scanner.ruleCount() + "   Findings: 0");
        }
    }

    private void loadRulesFromFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load rules.json");
        if (fc.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<Rule> rules = RuleLoader.loadFromFile(fc.getSelectedFile().toPath());
            scanner.updateRules(rules);
            statusLabel.setText("Rules: " + scanner.ruleCount()
                    + "   Findings: " + tableModel.getRowCount());
            JOptionPane.showMessageDialog(panel, "Loaded " + rules.size() + " rules.",
                    "Secret Scanner", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(panel, "Failed to load rules: " + ex.getMessage(),
                    "Secret Scanner", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportJson() {
        List<Finding> findings = tableModel.getAllFindings();
        if (findings.isEmpty()) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("secret_findings.json"));
        if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        try (PrintWriter pw = new PrintWriter(
                new FileWriter(fc.getSelectedFile(), StandardCharsets.UTF_8))) {
            pw.println("[");
            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                pw.print("  {");
                pw.print("\"id\":\"" + f.id() + "\"");
                pw.print(",\"timestamp\":\"" + f.timestampFormatted() + "\"");
                pw.print(",\"ruleId\":\"" + jsonEsc(f.rule().id()) + "\"");
                pw.print(",\"ruleName\":\"" + jsonEsc(f.rule().name()) + "\"");
                pw.print(",\"severity\":\"" + f.rule().severity() + "\"");
                pw.print(",\"host\":\"" + jsonEsc(f.host()) + "\"");
                pw.print(",\"url\":\"" + jsonEsc(f.url()) + "\"");
                pw.print(",\"match\":\"" + jsonEsc(f.match()) + "\"");
                pw.print(",\"context\":\"" + jsonEsc(f.context()) + "\"");
                pw.print(",\"entropy\":" + String.format("%.4f", f.entropy()));
                pw.print(",\"bodyOffset\":" + f.bodyOffset());
                pw.print(",\"validated\":\"" + f.validationResult() + "\"");
                pw.print("}");
                if (i < findings.size() - 1) pw.print(",");
                pw.println();
            }
            pw.println("]");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(panel, "Export failed: " + ex.getMessage(),
                    "Secret Scanner", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    // ── Severity cell renderer ────────────────────────────────────────────────

    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, col);
            if (!selected) {
                String sev = value == null ? "" : value.toString();
                c.setBackground(switch (sev) {
                    case "CRITICAL" -> new Color(255, 100, 100);
                    case "HIGH"     -> new Color(255, 160, 50);
                    case "MEDIUM"   -> new Color(255, 230, 80);
                    default         -> Color.LIGHT_GRAY;
                });
                c.setForeground(Color.BLACK);
            }
            return c;
        }
    }
}
