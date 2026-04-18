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
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SecretScannerTab {

    private final JPanel panel;
    private final FindingsTableModel tableModel;
    private final JTable table;
    private final TableRowSorter<FindingsTableModel> sorter;
    private final DetailPane detailPane;
    private final JCheckBox autoScanCheckbox;
    private final JCheckBox showFPsCheckbox;
    private final JLabel statusLabel;
    private final JLabel capWarning;
    private final SecretScanner scanner;
    private final ValidatorRegistry validators;

    private final AtomicBoolean autoScan = new AtomicBoolean(false);

    public SecretScannerTab(SecretScanner scanner, ValidatorRegistry validators,
                            DetailPane detailPane) {
        this.scanner = scanner;
        this.validators = validators;
        this.tableModel = new FindingsTableModel();
        this.table = new JTable(tableModel);
        this.sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        this.detailPane = detailPane;
        detailPane.setTableModel(tableModel);

        this.autoScanCheckbox = new JCheckBox("Auto-scan all responses", false);
        this.showFPsCheckbox  = new JCheckBox("Show FPs", false);
        this.statusLabel = new JLabel("Rules: " + scanner.ruleCount() + "   Findings: 0");
        this.capWarning = new JLabel("");
        capWarning.setForeground(Color.RED);

        autoScanCheckbox.addActionListener(e -> autoScan.set(autoScanCheckbox.isSelected()));
        showFPsCheckbox.addActionListener(e -> applyFPFilter());

        configureTable();
        this.panel = buildPanel();
        attachContextMenu();
        applyFPFilter();
    }

    private void configureTable() {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(FindingsTableModel.COL_TIME).setPreferredWidth(140);
        table.getColumnModel().getColumn(FindingsTableModel.COL_RULE).setPreferredWidth(200);
        table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY).setPreferredWidth(70);
        table.getColumnModel().getColumn(FindingsTableModel.COL_HOST).setPreferredWidth(150);
        table.getColumnModel().getColumn(FindingsTableModel.COL_URL).setPreferredWidth(200);
        table.getColumnModel().getColumn(FindingsTableModel.COL_MATCH).setPreferredWidth(180);
        table.getColumnModel().getColumn(FindingsTableModel.COL_ENTROPY).setPreferredWidth(60);
        table.getColumnModel().getColumn(FindingsTableModel.COL_VALIDATED).setPreferredWidth(90);

        table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY)
                .setCellRenderer(new SeverityRenderer());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) { detailPane.show(null); return; }
            int modelRow = table.convertRowIndexToModel(viewRow);
            detailPane.show(tableModel.getRow(modelRow));
        });

        // Ctrl+C → Copy URL (most common triage action)
        table.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copyUrl");
        table.getActionMap().put("copyUrl", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                copyUrls();
            }
        });
    }

    private JPanel buildPanel() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        toolbar.add(autoScanCheckbox);
        toolbar.add(showFPsCheckbox);

        JButton loadRulesBtn = new JButton("Load rules\u2026");
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

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), detailPane);
        split.setDividerLocation(300);
        split.setResizeWeight(0.65);

        p.add(toolbar, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void attachContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem copyMatch    = new JMenuItem("Copy match");
        JMenuItem copyUrl      = new JMenuItem("Copy URL");
        JMenuItem copyHost     = new JMenuItem("Copy host");
        JMenuItem copyJson     = new JMenuItem("Copy as JSON");
        JMenuItem copyCurl     = new JMenuItem("Copy curl PoC");
        JMenuItem sendRepeater = new JMenuItem("Send request to Repeater");
        JMenuItem openBrowser  = new JMenuItem("Open URL in browser");
        JMenuItem validateKey  = new JMenuItem("Validate key");
        JMenuItem markFP       = new JMenuItem("Mark as false positive");
        JMenuItem deleteFinding= new JMenuItem("Delete finding");

        copyMatch.addActionListener(e -> copyField(Finding::match));
        copyUrl.addActionListener(e -> copyUrls());
        copyHost.addActionListener(e -> copyField(Finding::host));
        copyJson.addActionListener(e -> copyAsJson());
        copyCurl.addActionListener(e -> copyCurlPoC());
        openBrowser.addActionListener(e -> openInBrowser());
        validateKey.addActionListener(e -> validateSelected());
        markFP.addActionListener(e -> markFalsePositive());
        deleteFinding.addActionListener(e -> deleteSelected());

        popup.add(copyMatch);
        popup.add(copyUrl);
        popup.add(copyHost);
        popup.add(copyJson);
        popup.add(copyCurl);
        popup.addSeparator();
        popup.add(sendRepeater);
        popup.add(openBrowser);
        popup.addSeparator();
        popup.add(validateKey);
        popup.add(markFP);
        popup.add(deleteFinding);

        // Disable items dynamically before showing popup
        popup.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                List<Finding> sel = getSelectedFindings();
                boolean any = !sel.isEmpty();
                copyMatch.setEnabled(any);
                copyUrl.setEnabled(any);
                copyHost.setEnabled(any);
                copyJson.setEnabled(any);
                openBrowser.setEnabled(any);
                sendRepeater.setEnabled(false); // no MontoyaApi reference; disabled
                validateKey.setEnabled(any && sel.stream().anyMatch(
                        f -> validators.get(f.rule().validatorId()) != null && !f.isPendingValidation()));
                markFP.setEnabled(any);
                deleteFinding.setEnabled(any);
                copyCurl.setEnabled(any && sel.stream().anyMatch(
                        f -> buildCurlPoC(f) != null));
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });

        table.setComponentPopupMenu(popup);

        // Also allow right-click to select row if not already selected
        table.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                }
            }
        });
    }

    // ── Selection helpers ─────────────────────────────────────────────────────

    private List<Finding> getSelectedFindings() {
        List<Finding> result = new ArrayList<>();
        for (int viewRow : table.getSelectedRows()) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            Finding f = tableModel.getRow(modelRow);
            if (f != null) result.add(f);
        }
        return result;
    }

    // ── Copy actions ──────────────────────────────────────────────────────────

    private void copyField(java.util.function.Function<Finding, String> extractor) {
        List<Finding> sel = getSelectedFindings();
        if (sel.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        for (Finding f : sel) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(extractor.apply(f));
        }
        setClipboard(sb.toString());
    }

    private void copyUrls() {
        copyField(Finding::url);
    }

    private void copyAsJson() {
        List<Finding> sel = getSelectedFindings();
        if (sel.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        if (sel.size() > 1) sb.append("[\n");
        for (int i = 0; i < sel.size(); i++) {
            Finding f = sel.get(i);
            if (i > 0) sb.append(",\n");
            sb.append("{");
            sb.append("\"rule\":\"").append(jsonEsc(f.rule().id())).append("\"");
            sb.append(",\"severity\":\"").append(f.effectiveSeverity()).append("\"");
            sb.append(",\"declaredSeverity\":\"").append(f.rule().severity()).append("\"");
            sb.append(",\"url\":\"").append(jsonEsc(f.url())).append("\"");
            sb.append(",\"host\":\"").append(jsonEsc(f.host())).append("\"");
            sb.append(",\"match\":\"").append(jsonEsc(f.match())).append("\"");
            sb.append(",\"entropy\":").append(String.format("%.4f", f.entropy()));
            sb.append(",\"validated\":\"").append(f.validationResult()).append("\"");
            sb.append(",\"timestamp\":\"").append(f.timestampFormatted()).append("\"");
            sb.append("}");
        }
        if (sel.size() > 1) sb.append("\n]");
        setClipboard(sb.toString());
    }

    private void copyCurlPoC() {
        List<Finding> sel = getSelectedFindings();
        if (sel.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        for (Finding f : sel) {
            String curl = buildCurlPoC(f);
            if (curl != null) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(curl);
            }
        }
        if (sb.length() > 0) setClipboard(sb.toString());
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    private void openInBrowser() {
        for (Finding f : getSelectedFindings()) {
            try {
                Desktop.getDesktop().browse(new URI(f.url()));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel,
                        "Cannot open URL: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void validateSelected() {
        for (Finding f : getSelectedFindings()) {
            detailPane.validateFinding(f);
        }
    }

    private void markFalsePositive() {
        for (Finding f : getSelectedFindings()) {
            f.setFalsePositive(true);
        }
        applyFPFilter();
        updateStatus();
    }

    private void deleteSelected() {
        List<Finding> sel = getSelectedFindings();
        if (sel.isEmpty()) return;
        tableModel.removeFindings(sel);
        updateStatus();
    }

    // ── FP filter ─────────────────────────────────────────────────────────────

    private void applyFPFilter() {
        if (showFPsCheckbox.isSelected()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(new javax.swing.RowFilter<>() {
                @Override
                public boolean include(Entry<? extends FindingsTableModel, ? extends Integer> entry) {
                    Finding f = tableModel.getRow(entry.getIdentifier());
                    return f != null && !f.isFalsePositive();
                }
            });
        }
    }

    // ── Curl PoC builder ──────────────────────────────────────────────────────

    static String buildCurlPoC(Finding f) {
        String key = f.match().replace("'", "'\\''");
        String vid = f.rule().validatorId();
        if (vid == null) return null;
        return switch (vid) {
            case "anthropic" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.anthropic.com/v1/models' -H 'x-api-key: %s' -H 'anthropic-version: 2023-06-01'", key);
            case "openai" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.openai.com/v1/models' -H 'Authorization: Bearer %s'", key);
            case "gemini" -> String.format(
                "curl -s 'https://generativelanguage.googleapis.com/v1beta/models?key=%s'", key);
            case "huggingface" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://huggingface.co/api/whoami-v2' -H 'Authorization: Bearer %s'", key);
            case "grok" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.x.ai/v1/models' -H 'Authorization: Bearer %s'", key);
            case "groq" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.groq.com/openai/v1/models' -H 'Authorization: Bearer %s'", key);
            case "replicate" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.replicate.com/v1/account' -H 'Authorization: Bearer %s'", key);
            case "github" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.github.com/user' -H 'Authorization: Bearer %s' -H 'Accept: application/vnd.github+json'", key);
            case "slack" -> String.format(
                "curl -s -X POST 'https://slack.com/api/auth.test' -H 'Authorization: Bearer %s' -H 'Content-Type: application/json'", key);
            case "stripe" -> String.format(
                "curl -s -o /dev/null -w '%%{http_code}' 'https://api.stripe.com/v1/charges?limit=1' -u '%s:'", key);
            default -> null;
        };
    }

    // ── Public API ────────────────────────────────────────────────────────────

    public JPanel getPanel() { return panel; }
    public boolean isAutoScanEnabled() { return autoScan.get(); }

    public void addFinding(Finding f) {
        SwingUtilities.invokeLater(() -> {
            boolean ok = tableModel.addFinding(f);
            if (!ok) capWarning.setText("\u26a0 Cap reached: oldest findings dropped");
            updateStatus();
        });
    }

    private void updateStatus() {
        statusLabel.setText("Rules: " + scanner.ruleCount()
                + "   Findings: " + tableModel.getRowCount());
    }

    private void clearFindings() {
        int res = JOptionPane.showConfirmDialog(panel,
                "Clear all findings?", "Secret Scanner", JOptionPane.YES_NO_OPTION);
        if (res == JOptionPane.YES_OPTION) {
            tableModel.clear();
            capWarning.setText("");
            updateStatus();
        }
    }

    private void loadRulesFromFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load rules.json");
        if (fc.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<Rule> rules = RuleLoader.loadFromFile(fc.getSelectedFile().toPath());
            scanner.updateRules(rules);
            updateStatus();
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
                pw.print(",\"severity\":\"" + f.effectiveSeverity() + "\"");
                pw.print(",\"declaredSeverity\":\"" + f.rule().severity() + "\"");
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

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static void setClipboard(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(s), null);
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
