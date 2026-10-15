// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonObject;
import com.littlespidy.jwtcomparator.model.JwtKeyOperations;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;

/** Key generation, JWT signing/verification and JWKS verification. */
public class JwtKeyOperationsPanel extends JPanel {
    private final MontoyaApi api;
    private final JComboBox<String> algorithm = new JComboBox<>(new String[]{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"});
    private final JTextArea token = new JTextArea(3, 70);
    private final JTextArea claims = new JTextArea("{\n  \"sub\": \"user123\",\n  \"iat\": 0,\n  \"role\": \"user\"\n}", 3, 70);
    private final JTextArea privateKey = new JTextArea(7, 48);
    private final JTextArea publicKey = new JTextArea(7, 48);
    private final JTextArea certificateBase64 = new JTextArea(2, 70);
    private final JPasswordField secret = new JPasswordField(28);
    private final JTextField jwksUrl = new JTextField(42);
    private final JTextArea output = new JTextArea(7, 80);

    public JwtKeyOperationsPanel(MontoyaApi api) {
        super(new BorderLayout(6, 6)); this.api = api;
        JPanel form = new JPanel(new GridBagLayout()); GridBagConstraints c = new GridBagConstraints(); c.insets = new Insets(3,5,3,5); c.fill=GridBagConstraints.BOTH; c.weightx=1;
        c.gridx=0;c.gridy=0;c.weightx=0;form.add(new JLabel("Algorithm:"),c); c.gridx=1;c.weightx=1;form.add(algorithm,c);
        c.gridx=0;c.gridy++;c.weightx=0;form.add(new JLabel("JWT:"),c); c.gridx=1;c.weightx=1;form.add(new JScrollPane(token),c);
        c.gridx=0;c.gridy++;c.weightx=0;form.add(new JLabel("Claims JSON (create):"),c); c.gridx=1;c.weightx=1;form.add(new JScrollPane(claims),c);
        c.gridx=0;c.gridy++;c.weightx=0;form.add(new JLabel("HMAC secret:"),c); c.gridx=1;c.weightx=1;form.add(secret,c);
        JPanel keys=new JPanel(new GridLayout(1,2,5,5)); privateKey.setLineWrap(false); publicKey.setLineWrap(false);
        keys.add(titled("Private key (PKCS#8 PEM)", privateKey)); keys.add(titled("Public key (X.509 PEM)", publicKey));
        c.gridx=0;c.gridy++;c.gridwidth=2;c.weighty=1;form.add(keys,c);
        c.gridy++;c.weighty=0;form.add(titled("Self-signed certificate DER, base64 (for x5c)",new JScrollPane(certificateBase64)),c);
        JPanel url=new JPanel(new BorderLayout(5,0)); url.add(new JLabel("JWKS URL:"),BorderLayout.WEST); url.add(jwksUrl,BorderLayout.CENTER);
        c.gridy++;c.weighty=0;form.add(url,c);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton generate=new JButton("Generate Key / Secret"); generate.addActionListener(e->generate()); actions.add(generate);
        JButton create=new JButton("Create JWT"); create.addActionListener(e->create()); actions.add(create);
        JButton sign=new JButton("Sign / Re-sign JWT"); sign.addActionListener(e->sign()); actions.add(sign);
        JButton verify=new JButton("Verify JWT"); verify.addActionListener(e->verify()); actions.add(verify);
        JButton verifyJwks=new JButton("Fetch JWKS & Verify"); verifyJwks.addActionListener(e->verifyJwks()); actions.add(verifyJwks);
        c.gridy++;form.add(actions,c);
        output.setEditable(false); output.setLineWrap(true); output.setWrapStyleWord(true);
        JSplitPane split=new JSplitPane(JSplitPane.VERTICAL_SPLIT,form,titled("Operation output",new JScrollPane(output))); split.setResizeWeight(.7);
        add(split,BorderLayout.CENTER);
    }

    private JPanel titled(String title, Component component) { JPanel p=new JPanel(new BorderLayout()); p.setBorder(BorderFactory.createTitledBorder(title)); p.add(component); return p; }
    private void generate() {
        String alg=(String)algorithm.getSelectedItem();
        try {
            if(alg.startsWith("HS")) { int n=alg.endsWith("256")?32:alg.endsWith("384")?48:64; byte[] bytes=new byte[n]; new SecureRandom().nextBytes(bytes); secret.setText(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)); privateKey.setText("");publicKey.setText("");certificateBase64.setText(""); report(alg+" secret generated (base64url, "+n+" bytes). Store it securely."); }
            else { KeyPair pair=JwtKeyOperations.generateKeyPair(alg); privateKey.setText(JwtKeyOperations.toPem("PRIVATE KEY",pair.getPrivate().getEncoded())); publicKey.setText(JwtKeyOperations.toPem("PUBLIC KEY",pair.getPublic().getEncoded())); certificateBase64.setText(Base64.getEncoder().encodeToString(JwtKeyOperations.selfSignedCertificate(pair,alg))); report(alg+" key pair and self-signed certificate generated. Private PKCS#8, public X.509 PEM, certificate DER, and public JWK are ready."); }
        } catch(Exception ex) { report("Key generation failed: "+ex.getMessage()); }
    }
    private void create() { try { String created=JwtKeyOperations.create(claims.getText(),(String)algorithm.getSelectedItem(),new String(secret.getPassword()),privateKey.getText()); token.setText(created); report("New JWT created and signed with "+algorithm.getSelectedItem()+"."); } catch(Exception ex) { report("Creation failed: "+ex.getMessage()); } }
    private void sign() { try { String signed=JwtKeyOperations.sign(token.getText().trim(),(String)algorithm.getSelectedItem(),new String(secret.getPassword()),privateKey.getText()); token.setText(signed); report("Token signed with "+algorithm.getSelectedItem()+"."); } catch(Exception ex) { report("Signing failed: "+ex.getMessage()); } }
    private void verify() { try { boolean valid=JwtKeyOperations.verify(token.getText().trim(),new String(secret.getPassword()),publicKey.getText()); report("Signature "+(valid?"VALID":"INVALID")+" for "+algorithmFromToken()+"."); } catch(Exception ex) { report("Verification failed: "+ex.getMessage()); } }
    private String algorithmFromToken() { try { String p=token.getText().trim().split("\\.",-1)[0]; return JsonParser.parseString(new String(Base64.getUrlDecoder().decode(p+"=".repeat((4-p.length()%4)%4)),StandardCharsets.UTF_8)).getAsJsonObject().get("alg").getAsString(); } catch(Exception e) { return "unknown algorithm"; } }
    private void verifyJwks() {
        String url=jwksUrl.getText().trim(); if(url.isEmpty()) { report("Enter a JWKS URL."); return; }
        new SwingWorker<String,Void>() {
            protected String doInBackground() throws Exception {
                if(api==null || api.http()==null) throw new IllegalStateException("Burp HTTP API is unavailable.");
                var rr=api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
                if(rr==null || !rr.hasResponse()) throw new IllegalStateException("JWKS endpoint returned no response.");
                int status=rr.response().statusCode(); if(status<200||status>=300) throw new IllegalStateException("JWKS endpoint returned HTTP "+status);
                JsonObject jwks=JsonParser.parseString(rr.response().bodyToString()).getAsJsonObject(); JsonArray keys=jwks.getAsJsonArray("keys");
                String[] p=token.getText().trim().split("\\.",-1); JsonObject header=JsonParser.parseString(new String(Base64.getUrlDecoder().decode(p[0]+"=".repeat((4-p[0].length()%4)%4)),StandardCharsets.UTF_8)).getAsJsonObject();
                String kid=header.has("kid")?header.get("kid").getAsString():null; String alg=header.get("alg").getAsString(); int tried=0;
                for(var item:keys) { JsonObject key=item.getAsJsonObject(); if(kid!=null && key.has("kid") && !kid.equals(key.get("kid").getAsString())) continue; if(key.has("use") && !"sig".equals(key.get("use").getAsString())) continue; if(key.has("alg")&&!alg.equals(key.get("alg").getAsString()))continue; tried++; try { if(JwtKeyOperations.verifyWithPublicKey(token.getText().trim(),JwtKeyOperations.jwkPublicKey(key))) return "Signature VALID using JWKS key "+(key.has("kid")?key.get("kid").getAsString():"(no kid)")+" ("+alg+")."; } catch(Exception ignored) { /* Skip nonmatching JWKS key types. */ } }
                return "No matching JWKS key verified the signature (keys tried: "+tried+").";
            }
            protected void done() { try { report(get()); } catch(Exception ex) { report("JWKS verification failed: "+ex.getCause().getMessage()); } }
        }.execute();
    }
    public String signVariant(JsonObject header, JsonObject payload) throws Exception {
        String alg=(String)algorithm.getSelectedItem(); header.addProperty("alg",alg);
        return JwtKeyOperations.sign(JwtKeyOperations.unsignedToken(header,payload),alg,new String(secret.getPassword()),privateKey.getText());
    }
    public JsonObject publicJwk() throws Exception { JsonObject jwk=JwtKeyOperations.publicJwkFromPem(publicKey.getText(),(String)algorithm.getSelectedItem(),"jwt-playbook-key"); jwk.addProperty("alg",algorithm.getSelectedItem().toString()); return jwk; }
    public boolean hasPrivateKey() { return !((String)algorithm.getSelectedItem()).startsWith("HS")&&!privateKey.getText().isBlank(); }
    public byte[] certificateDer() { return Base64.getDecoder().decode(certificateBase64.getText().trim()); }
    private void report(String text) { output.append(text+"\n"); output.setCaretPosition(output.getDocument().getLength()); }
}
