package io.github.abdallah.secretscanner.ui;

import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.model.ValidationResult;
import io.github.abdallah.secretscanner.validator.Validator;
import io.github.abdallah.secretscanner.validator.ValidatorRegistry;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.time.Instant;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

public final class DetailPane extends JPanel {

    private static final long VALIDATE_COOLDOWN_MS = 3_000;

    private final JLabel ruleLabel   = new JLabel(" ");
    private final JLabel regexLabel  = new JLabel(" ");
    private final JTextPane matchPane = new JTextPane();
    private final JTextPane ctxPane   = new JTextPane();
    private final JLabel metaLabel   = new JLabel(" ");
    private final JLabel validLabel  = new JLabel(" ");
    private final JButton validateBtn = new JButton("Validate");
    private final JButton copyBtn     = new JButton("Copy match");

    private volatile Finding current;
    private final ValidatorRegistry validators;
    private final ScheduledExecutorService executor;
    private final AtomicLong lastValidateMs = new AtomicLong(0);
    private final BiConsumer<Finding, FindingsTableModel> onValidated;
    private FindingsTableModel tableModel;

    public DetailPane(ValidatorRegistry validators, ScheduledExecutorService executor,
                      BiConsumer<Finding, FindingsTableModel> onValidated) {
        this.validators = validators;
        this.executor = executor;
        this.onValidated = onValidated;
        buildUI();
    }

    public void setTableModel(FindingsTableModel tm) {
        this.tableModel = tm;
    }

    private void buildUI() {
        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // Top meta info
        JPanel metaPanel = new JPanel(new GridLayout(2, 1, 2, 2));
        ruleLabel.setFont(ruleLabel.getFont().deriveFont(Font.BOLD));
        metaPanel.add(ruleLabel);
        metaPanel.add(regexLabel);

        // Match text (monospace, selectable)
        matchPane.setEditable(false);
        matchPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        matchPane.setBorder(BorderFactory.createTitledBorder("Match"));

        // Context text
        ctxPane.setEditable(false);
        ctxPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        ctxPane.setBorder(BorderFactory.createTitledBorder("Context (±80 chars)"));

        JSplitPane textSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(matchPane), new JScrollPane(ctxPane));
        textSplit.setDividerLocation(320);
        textSplit.setResizeWeight(0.3);

        // Bottom bar
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
        ruleLabel.setText(f.rule().severity() + " | " + f.rule().name());
        regexLabel.setText("Regex: " + f.rule().rawRegex());
        matchPane.setText(f.match());
        ctxPane.setText(f.context());
        metaLabel.setText(String.format("Entropy: %.2f    Offset: %,d", f.entropy(), f.bodyOffset()));
        updateValidLabel(f);
        boolean hasValidator = validators.get(f.rule().validatorId()) != null;
        validateBtn.setEnabled(hasValidator);
    }

    private void updateValidLabel(Finding f) {
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

    private void doValidate() {
        Finding f = current;
        if (f == null) return;
        long now = System.currentTimeMillis();
        if (now - lastValidateMs.get() < VALIDATE_COOLDOWN_MS) {
            JOptionPane.showMessageDialog(this,
                    "Please wait " + VALIDATE_COOLDOWN_MS / 1000 + " seconds between validations.",
                    "Rate limit", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Validator v = validators.get(f.rule().validatorId());
        if (v == null) return;
        lastValidateMs.set(now);
        validateBtn.setEnabled(false);
        executor.submit(() -> {
            ValidationResult result;
            try {
                result = v.validate(f.match());
            } catch (Exception e) {
                result = ValidationResult.NETWORK_ERROR;
            }
            ValidationResult finalResult = result;
            f.setValidation(finalResult, Instant.now());
            SwingUtilities.invokeLater(() -> {
                updateValidLabel(f);
                validateBtn.setEnabled(true);
                if (tableModel != null) tableModel.refreshRow(f);
                if (onValidated != null) onValidated.accept(f, tableModel);
            });
        });
    }

    private void doCopy() {
        Finding f = current;
        if (f == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(f.match()), null);
    }
}
