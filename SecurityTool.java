import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.Base64;

public class SecurityTool {
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private JFrame frame;
    private JTextField keyField, inputField, outputField, hashOutputField;
    private JButton generateKeyButton, encryptButton, decryptButton, encryptFileButton, decryptFileButton, generateHashButton;
    private JFileChooser fileChooser;
    private SecretKey secretKey;
    private File currentFile = null;

    public SecurityTool() {
        frame = new JFrame("AES Encryption Tool");
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new GridLayout(6, 1, 5, 5));

        keyField = new JTextField(32);
        inputField = new JTextField(32);
        outputField = new JTextField(32);
        outputField.setEditable(false);
        hashOutputField = new JTextField(64);
        hashOutputField.setEditable(false);

        generateKeyButton = new JButton("Generate Key");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        encryptFileButton = new JButton("Encrypt File");
        decryptFileButton = new JButton("Decrypt File");
        generateHashButton = new JButton("Generate Hash");

        fileChooser = new JFileChooser();

        createMenuBar();

        JPanel keyPanel = new JPanel();
        keyPanel.add(new JLabel("AES Key:"));
        keyPanel.add(keyField);
        keyPanel.add(generateKeyButton);

        JPanel textPanel = new JPanel();
        textPanel.add(new JLabel("Input:"));
        textPanel.add(inputField);
        textPanel.add(encryptButton);
        textPanel.add(decryptButton);

        JPanel outputPanel = new JPanel();
        outputPanel.add(new JLabel("Output:"));
        outputPanel.add(outputField);

        JPanel hashPanel = new JPanel();
        hashPanel.add(new JLabel("Hash Output:"));
        hashPanel.add(hashOutputField);
        hashPanel.add(generateHashButton);

        JPanel filePanel = new JPanel();
        filePanel.add(encryptFileButton);
        filePanel.add(decryptFileButton);

        frame.add(keyPanel);
        frame.add(textPanel);
        frame.add(outputPanel);
        frame.add(hashPanel);
        frame.add(filePanel);

        generateKeyButton.addActionListener(e -> generateKey());
        encryptButton.addActionListener(e -> encryptText());
        decryptButton.addActionListener(e -> decryptText());
        encryptFileButton.addActionListener(e -> encryptFile());
        decryptFileButton.addActionListener(e -> decryptFile());
        generateHashButton.addActionListener(e -> generateHash());

        frame.setVisible(true);
    }

    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenu helpMenu = new JMenu("Help");

        JMenuItem newItem = new JMenuItem("New");
        JMenuItem openItem = new JMenuItem("Open");
        JMenuItem saveItem = new JMenuItem("Save");
        JMenuItem saveAsItem = new JMenuItem("Save As");
        JMenuItem helpItem = new JMenuItem("Help");

        newItem.addActionListener(e -> createNewFile());
        openItem.addActionListener(this::openFile);
        saveItem.addActionListener(e -> saveToFile());
        saveAsItem.addActionListener(e -> saveToFileAs());
        helpItem.addActionListener(e -> showHelp());

        fileMenu.add(newItem);
        fileMenu.add(openItem);
        fileMenu.add(saveItem);
        fileMenu.add(saveAsItem);
        helpMenu.add(helpItem);

        menuBar.add(fileMenu);
        menuBar.add(helpMenu);

        frame.setJMenuBar(menuBar);
    }

    private void createNewFile() {
        inputField.setText("");
        outputField.setText("");
        hashOutputField.setText("");
        keyField.setText("");
        currentFile = null;
        frame.setTitle("AES Encryption Tool - New File");
    }

    private void generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
            keyField.setText(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        } catch (Exception e) {
            showError("Key Generation Failed");
        }
    }

    private SecretKey getSecretKeyFromField() {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(keyField.getText());
            return new SecretKeySpec(decodedKey, "AES");
        } catch (Exception e) {
            return null;
        }
    }

    private void encryptText() {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyFromField());
            byte[] encrypted = cipher.doFinal(inputField.getText().getBytes());
            outputField.setText(Base64.getEncoder().encodeToString(encrypted));
        } catch (Exception e) {
            showError("Encryption Failed");
        }
    }

    private void decryptText() {
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKeyFromField());
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(outputField.getText()));
            inputField.setText(new String(decrypted));
        } catch (Exception e) {
            showError("Decryption Failed");
        }
    }
    private void encryptFile() {
        if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                byte[] fileData = Files.readAllBytes(file.toPath());
                Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyFromField());
                byte[] encryptedData = cipher.doFinal(fileData);

                Path encryptedPath = Paths.get(file.getAbsolutePath() + ".enc");
                Files.write(encryptedPath, encryptedData);
                showSuccess("File Encrypted Successfully: " + encryptedPath);
            } catch (Exception e) {
                showError("File Encryption Failed");
            }
        }
    }

    private void decryptFile() {
        if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                byte[] fileData = Files.readAllBytes(file.toPath());
    
                SecretKey key = getSecretKeyFromField();
                if (key == null) {
                    showError("Invalid AES Key. Please provide a valid key.");
                    return;
                }
    
                Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decryptedData = cipher.doFinal(fileData);
    
                Path decryptedPath = Paths.get(file.getAbsolutePath().replace(".enc", ""));
                Files.write(decryptedPath, decryptedData);
                showSuccess("File Decrypted Successfully: " + decryptedPath);
            } catch (BadPaddingException e) {
                showError("Decryption failed! Incorrect key or corrupted file.");
            } catch (Exception e) {
                showError("File Decryption Failed: " + e.getMessage());
            }
        }
    }
    

    private void generateHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(inputField.getText().getBytes(StandardCharsets.UTF_8));
            hashOutputField.setText(Base64.getEncoder().encodeToString(hash));
        } catch (Exception e) {
            showError("Hash Generation Failed");
        }
    }

    private void openFile(ActionEvent e) {
        if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            currentFile = fileChooser.getSelectedFile();
            try {
                String content = Files.readString(currentFile.toPath());
                inputField.setText(content);
                frame.setTitle("AES Encryption Tool - " + currentFile.getName());
            } catch (IOException ex) {
                showError("Failed to Open File");
            }
        }
    }

    private void saveToFile() {
        if (currentFile == null) {
            saveToFileAs();
        } else {
            try {
                Files.writeString(currentFile.toPath(), inputField.getText());
                showSuccess("File Saved Successfully!");
            } catch (IOException e) {
                showError("Failed to Save File");
            }
        }
    }

    private void saveToFileAs() {
        if (fileChooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            currentFile = fileChooser.getSelectedFile();
            saveToFile();
        }
    }

    private void showHelp() {
        JOptionPane.showMessageDialog(frame,
                "AES Encryption Tool Instructions:\n" +
                        "1. Generate an AES key and store it safely.\n" +
                        "2. Enter text and click Encrypt/Decrypt.\n" +
                        "3. Use File Menu to save and open files.\n" +
                        "4. Use Encrypt File / Decrypt File to secure files.",
                "Help", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(frame, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void showSuccess(String message) {
        JOptionPane.showMessageDialog(frame, message, "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SecurityTool::new);
    }
}
