package io.github.abdallah.secretscanner.ui;

import io.github.abdallah.secretscanner.engine.Rule;
import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.model.ValidationResult;
import io.github.abdallah.secretscanner.validator.ValidationThrottle;
import io.github.abdallah.secretscanner.validator.Validator;
import io.github.abdallah.secretscanner.validator.ValidatorRegistry;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.util.concurrent.ExecutorService;

public final class DetailPane extends JPanel {

    private final JLabel ruleLabel   = new JLabel(" ");
    private final JLabel regexLabel  = new JLabel(" ");
    private final JTextArea matchPane = new JTextArea();
    private final JTextArea ctxPane   = new JTextArea();
    private final JLabel metaLabel   = new JLabel(" ");
    private final JLabel validLabel  = new JLabel(" ");
    private final JButton validateBtn = new JButton("Validate");
    private final JButton copyBtn     = new JButton("Copy match");

    private volatile Finding current;
    private final ValidatorRegistry validators;
    private final ExecutorService executor;
    private final ValidationThrottle throttle;
    private FindingsTableModel tableModel;

    public DetailPane(ValidatorRegistry validators, ExecutorService executor,
                      ValidationThrottle throttle) {
        this.validators = validators;
        this.executor = executor;
        this.throttle = throttle;
        buildUI();
    }

    public void setTableModel(FindingsTableModel tm) {
        this.tableModel = tm;
    }

    private void buildUI() {
        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel metaPanel = new JPanel(new GridLayout(2, 1, 2, 2));
        ruleLabel.setFont(ruleLabel.getFont().deriveFont(Font.BOLD));
        metaPanel.add(ruleLabel);
        metaPanel.add(regexLabel);

        matchPane.setEditable(false);
        matchPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        matchPane.setLineWrap(true);
        matchPane.setRows(4);
        JScrollPane matchScroll = new JScrollPane(matchPane);
        matchScroll.setBorder(BorderFactory.createTitledBorder("Match"));

        ctxPane.setEditable(false);
        ctxPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        ctxPane.setLineWrap(true);
        ctxPane.setRows(4);
        JScrollPane ctxScroll = new JScrollPane(ctxPane);
        ctxScroll.setBorder(BorderFactory.createTitledBorder("Context (\u00b180 chars)"));

        JSplitPane textSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                matchScroll, ctxScroll);
        textSplit.setDividerLocation(320);
        textSplit.setResizeWeight(0.3);

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        bottomBar.add(metaLabel);
        bottomBar.add(validLabel);
        bottomBar.add(validateBtn);
        bottomBar.add(copyBtn);

        add(metaPanel, BorderLayout.NORTH);
        add(textSplit, BorderLayout.CENTER);
        add(bottomBar, BorderLayout.SOUTH);

        validateBtn.setEnabled(false);
        validateBtn.addActionListener(e -> doValidate());
        copyBtn.addActionListener(e -> doCopy());
    }

    public void show(Finding f) {
        current = f;
        if (f == null) {
            ruleLabel.setText(" ");
            regexLabel.setText(" ");
            matchPane.setText("");
            ctxPane.setText("");
            metaLabel.setText(" ");
            validLabel.setText(" ");
            validateBtn.setEnabled(false);
            return;
        }
        ruleLabel.setText(f.effectiveSeverity() + " | " + f.rule().name());
        regexLabel.setText("Regex: " + f.rule().rawRegex());
        String matchText = f.match();
        if (matchText.length() > 4096) matchText = matchText.substring(0, 4096) + "\n[truncated]";
        matchPane.setText(matchText);
        matchPane.setCaretPosition(0);
        ctxPane.setText(f.context());
        ctxPane.setCaretPosition(0);
        metaLabel.setText(String.format("Entropy: %.2f    Offset: %,d", f.entropy(), f.bodyOffset()));
        updateValidLabel(f);
        boolean hasValidator = validators.get(f.rule().validatorId()) != null;
        validateBtn.setEnabled(hasValidator && !f.isPendingValidation());
    }

    private void updateValidLabel(Finding f) {
        if (f.isPendingValidation()) { validLabel.setText("Validating\u2026"); return; }
        String text = switch (f.validationResult()) {
            case NOT_CHECKED      -> "";
            case VALID            -> "\u2713 VALID";
            case INVALID          -> "\u2717 INVALID";
            case RATE_LIMITED     -> "Rate-limited";
            case NETWORK_ERROR    -> "Network error";
            case NOT_IMPLEMENTED  -> "Validation N/A (needs secret key pair)";
            default               -> "";
        };
        validLabel.setText(text);
    }

    public void validateFinding(Finding f) {
        if (f == null || f.isPendingValidation()) return;
        Validator v = validators.get(f.rule().validatorId());
        if (v == null) return;
        f.setPendingValidation(true);
        SwingUtilities.invokeLater(() -> {
            if (tableModel != null) tableModel.refreshRow(f);
            if (f == current) { updateValidLabel(f); validateBtn.setEnabled(false); }
        });
        executor.submit(() -> {
            try {
                throttle.executeThrottled(() -> {
                    ValidationResult result;
                    try {
                        result = v.validate(f.match());
                    } catch (Exception ex) {
                        result = ValidationResult.NETWORK_ERROR;
                    }
                    f.setValidation(result, Instant.now());
                    if (result == ValidationResult.VALID) {
                        if ("gemini".equals(f.rule().validatorId())
                                && f.rule().severity() == Rule.Severity.MEDIUM) {
                            f.setEffectiveSeverity(Rule.Severity.HIGH);
                        }
                    }
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                f.setPendingValidation(false);
            }
            SwingUtilities.invokeLater(() -> {
                if (tableModel != null) tableModel.refreshRow(f);
                if (f == current) {
                    updateValidLabel(f);
                    boolean hasValidator = validators.get(f.rule().validatorId()) != null;
                    validateBtn.setEnabled(hasValidator && !f.isPendingValidation());
                }
            });
        });
    }

    private void doValidate() {
        validateFinding(current);
    }

    private void doCopy() {
        Finding f = current;
        if (f == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(f.match()), null);
    }
}
