import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.Base64;
import java.nio.file.*;

public class SimplePasswordManager {

    private static final String MASTER_FILE = "master.key";
    private static final String VAULT_FILE = "vault.txt";
    private static SecretKey secretKey;
    private static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        if (!new File(MASTER_FILE).exists()) createMasterPassword();
        else if (!verifyMasterPassword()) return;

        secretKey = loadKey();

        while (true) {
            System.out.println("\n1.Add  2.View  3.Search  4.Update  5.Generate  6.Export  7.Import  8.Exit");
            System.out.print("Choose: ");
            int ch = sc.nextInt(); sc.nextLine();

            switch (ch) {
                case 1 -> addPassword();
                case 2 -> viewAll();
                case 3 -> searchPassword();
                case 4 -> updatePassword();
                case 5 -> System.out.println("Generated: " + generatePassword(12));
                case 6 -> exportVault();
                case 7 -> importVault();
                case 8 -> { System.out.println("Exit"); return; }
                default -> System.out.println("Invalid choice");
            }
        }
    }

    // Master Password
    private static void createMasterPassword() throws Exception {
        System.out.print("Create master password: ");
        String master = sc.nextLine();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(master.getBytes());
        try (FileOutputStream fos = new FileOutputStream(MASTER_FILE)) {
            fos.write(hash);
        }
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        try (FileOutputStream fos = new FileOutputStream("secret.key")) {
            fos.write(key.getEncoded());
        }
        System.out.println("Master password set!");
    }

    private static boolean verifyMasterPassword() throws Exception {
        System.out.print("Enter master password: ");
        String master = sc.nextLine();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] inputHash = md.digest(master.getBytes());
        byte[] storedHash = new FileInputStream(MASTER_FILE).readAllBytes();
        if (!Arrays.equals(inputHash, storedHash)) {
            System.out.println("Incorrect master password!");
            return false;
        }
        return true;
    }

    private static SecretKey loadKey() throws Exception {
        byte[] keyBytes = new FileInputStream("secret.key").readAllBytes();
        return new SecretKeySpec(keyBytes, "AES");
    }

    //Password Manager 
    private static void addPassword() throws Exception {
        System.out.print("Website: ");
        String site = sc.nextLine();
        System.out.print("Username: ");
        String user = sc.nextLine();
        System.out.print("Password: ");
        String pass = sc.nextLine();

        String data = site + "," + user + "," + pass;
        String enc = encrypt(data);
        try (FileWriter fw = new FileWriter(VAULT_FILE, true)) {
            fw.write(enc + "\n");
        }
        System.out.println("Saved!");
    }

    private static void viewAll() throws Exception {
        File f = new File(VAULT_FILE);
        if (!f.exists()) { System.out.println("No entries."); return; }
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            System.out.println("\n  Stored Passwords  ");
            while ((line = br.readLine()) != null) {
                String[] p = decrypt(line).split(",");
                System.out.println("Site: " + p[0] + ", User: " + p[1] + ", Pass: " + p[2]);
            }
        }
    }

    private static void searchPassword() throws Exception {
        System.out.print("Enter site name to search: ");
        String site = sc.nextLine().toLowerCase();
        File f = new File(VAULT_FILE);
        if (!f.exists()) { System.out.println("Vault empty."); return; }
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            boolean found = false;
            while ((line = br.readLine()) != null) {
                String[] p = decrypt(line).split(",");
                if (p[0].toLowerCase().contains(site)) {
                    System.out.println("Site: " + p[0] + ", User: " + p[1] + ", Pass: " + p[2]);
                    found = true;
                }
            }
            if (!found) System.out.println("No match found.");
        }
    }

    private static void updatePassword() throws Exception {
        System.out.print("Enter site to update: ");
        String site = sc.nextLine().toLowerCase();
        File f = new File(VAULT_FILE);
        if (!f.exists()) { System.out.println("No vault yet."); return; }

        List<String> lines = new ArrayList<>(Files.readAllLines(f.toPath()));
        boolean updated = false;
        for (int i = 0; i < lines.size(); i++) {
            String[] p = decrypt(lines.get(i)).split(",");
            if (p[0].toLowerCase().contains(site)) {
                System.out.print("New password: ");
                String newPass = sc.nextLine();
                String newData = p[0] + "," + p[1] + "," + newPass;
                lines.set(i, encrypt(newData));
                updated = true;
            }
        }
        Files.write(f.toPath(), lines);
        System.out.println(updated ? "Password updated!" : "Site not found.");
    }

    // ---------- Utility ----------
    private static String encrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes()));
    }

    private static String decrypt(String enc) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(enc)));
    }

    private static String generatePassword(int len) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(chars.charAt(r.nextInt(chars.length())));
        return sb.toString();
    }

    private static void exportVault() throws IOException {
        File f = new File(VAULT_FILE);
        if (!f.exists()) { System.out.println("No vault to export."); return; }
        Files.copy(f.toPath(), new File("vault_backup.txt").toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Vault exported to vault_backup.txt");
    }

    private static void importVault() throws IOException {
        File b = new File("vault_backup.txt");
        if (!b.exists()) { System.out.println("No backup found."); return; }
        Files.copy(b.toPath(), new File(VAULT_FILE).toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        System.out.println("Vault restored from backup.");
    }
}

