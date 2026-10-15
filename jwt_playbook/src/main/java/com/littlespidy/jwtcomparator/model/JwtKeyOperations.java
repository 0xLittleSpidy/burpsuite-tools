// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.PSSParameterSpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** JOSE signing, verification and key conversion for JWT workbench operations. */
public final class JwtKeyOperations {
    private JwtKeyOperations() {}

    public static KeyPair generateKeyPair(String alg) throws GeneralSecurityException {
        KeyPairGenerator generator;
        if (alg.startsWith("RS") || alg.startsWith("PS")) {
            generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        } else if (alg.startsWith("ES")) {
            generator = KeyPairGenerator.getInstance("EC");
            String curve = alg.endsWith("256") ? "secp256r1" : alg.endsWith("384") ? "secp384r1" : "secp521r1";
            generator.initialize(new ECGenParameterSpec(curve));
        } else if ("EdDSA".equals(alg)) {
            generator = KeyPairGenerator.getInstance("Ed25519");
        } else throw new IllegalArgumentException("Asymmetric algorithm required.");
        return generator.generateKeyPair();
    }

    public static String toPem(String type, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----";
    }
    public static PrivateKey privateKey(String pem, String alg) throws GeneralSecurityException {
        byte[] encoded = pemBytes(pem);
        String kind = "EdDSA".equals(alg) ? "Ed25519" : (alg.startsWith("ES") ? "EC" : "RSA");
        return KeyFactory.getInstance(kind).generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }
    public static PublicKey publicKey(String pem, String alg) throws GeneralSecurityException {
        byte[] encoded = pemBytes(pem);
        String kind = "EdDSA".equals(alg) ? "Ed25519" : (alg.startsWith("ES") ? "EC" : "RSA");
        return KeyFactory.getInstance(kind).generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static String sign(String token, String alg, String secret, String privatePem) throws Exception {
        String[] parts = parts(token);
        JsonObject header = object(decode(parts[0])); header.addProperty("alg", alg);
        String input = encode(header.toString()) + "." + parts[1];
        byte[] sig;
        if (alg.startsWith("HS")) sig = hmac(alg, secret.getBytes(StandardCharsets.UTF_8), input.getBytes(StandardCharsets.US_ASCII));
        else {
            Signature signer = Signature.getInstance(signatureName(alg));
            setPssParameters(signer, alg);
            signer.initSign(privateKey(privatePem, alg)); signer.update(input.getBytes(StandardCharsets.US_ASCII));
            sig = signer.sign(); if (alg.startsWith("ES")) sig = derToJose(sig, curveBytes(alg));
        }
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }
    public static String create(String claimsJson, String alg, String secret, String privatePem) throws Exception {
        JsonObject header=new JsonObject(); header.addProperty("typ","JWT"); header.addProperty("alg",alg);
        JsonObject claims=JsonParser.parseString(claimsJson).getAsJsonObject();
        return sign(encode(header.toString())+"."+encode(claims.toString())+".",alg,secret,privatePem);
    }
    public static String unsignedToken(JsonObject header, JsonObject claims) { return encode(header.toString())+"."+encode(claims.toString())+"."; }
    public static JsonObject publicJwkFromPem(String pem, String alg, String kid) throws Exception { return toPublicJwk(publicKey(pem,alg),kid); }
    public static byte[] selfSignedCertificate(KeyPair pair, String alg) throws Exception {
        String certAlg=alg.startsWith("PS")?"RS"+alg.substring(2):alg;
        String signerAlg=signatureName(certAlg);
        X500Name subject=new X500Name("CN=jwt_playbook test key");
        java.util.Date from=new java.util.Date(System.currentTimeMillis()-60_000L), to=new java.util.Date(System.currentTimeMillis()+365L*24*60*60*1000);
        byte[] serialBytes=new byte[16];new SecureRandom().nextBytes(serialBytes);
        JcaX509v3CertificateBuilder builder=new JcaX509v3CertificateBuilder(subject,new BigInteger(1,serialBytes),from,to,subject,pair.getPublic());
        ContentSigner signer=new JcaContentSignerBuilder(signerAlg).build(pair.getPrivate());
        X509CertificateHolder holder=builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder).getEncoded();
    }
    public static JsonObject toPublicJwk(PublicKey key, String kid) throws Exception {
        JsonObject jwk=new JsonObject(); if(kid!=null&&!kid.isBlank())jwk.addProperty("kid",kid); jwk.addProperty("use","sig");
        if(key instanceof RSAPublicKey rsa) { jwk.addProperty("kty","RSA"); jwk.addProperty("n",b64url(unsigned(rsa.getModulus()))); jwk.addProperty("e",b64url(unsigned(rsa.getPublicExponent()))); }
        else if(key instanceof ECPublicKey ec) {
            jwk.addProperty("kty","EC"); String curve=ec.getParams().getCurve().getField().getFieldSize()<=256?"P-256":ec.getParams().getCurve().getField().getFieldSize()<=384?"P-384":"P-521";
            int width=curve.equals("P-521")?66:curve.equals("P-384")?48:32; jwk.addProperty("crv",curve);
            jwk.addProperty("x",b64url(fixed(ec.getW().getAffineX(),width))); jwk.addProperty("y",b64url(fixed(ec.getW().getAffineY(),width)));
        } else if("EdDSA".equals(key.getAlgorithm())||"Ed25519".equals(key.getAlgorithm())) { byte[] encoded=key.getEncoded(); byte[] raw=java.util.Arrays.copyOfRange(encoded,encoded.length-32,encoded.length); jwk.addProperty("kty","OKP"); jwk.addProperty("crv","Ed25519"); jwk.addProperty("x",b64url(raw)); }
        else throw new IllegalArgumentException("Unsupported public key type: "+key.getAlgorithm());
        return jwk;
    }

    public static boolean verify(String token, String secret, String publicPem) throws Exception {
        String[] parts = parts(token); JsonObject header = object(decode(parts[0]));
        String alg = header.has("alg") ? header.get("alg").getAsString() : "";
        byte[] provided;
        try { provided = Base64.getUrlDecoder().decode(pad(parts[2])); }
        catch (IllegalArgumentException malformedSignature) { return false; }
        String input = parts[0] + "." + parts[1];
        if (alg.startsWith("HS")) return MessageDigest.isEqual(provided, hmac(alg, secret.getBytes(StandardCharsets.UTF_8), input.getBytes(StandardCharsets.US_ASCII)));
        return verifyWithPublicKey(token, publicKey(publicPem, alg));
    }
    public static boolean verifyWithPublicKey(String token, PublicKey key) throws Exception {
        String[] parts = parts(token); JsonObject header = object(decode(parts[0]));
        String alg = header.get("alg").getAsString();
        if (alg.startsWith("HS")) throw new IllegalArgumentException("HMAC verification requires a secret.");
        byte[] provided;
        try { provided = Base64.getUrlDecoder().decode(pad(parts[2])); }
        catch (IllegalArgumentException malformedSignature) { return false; }
        Signature verifier = Signature.getInstance(signatureName(alg)); setPssParameters(verifier, alg);
        verifier.initVerify(key); verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        try {
            if (alg.startsWith("ES")) provided = joseToDer(provided, curveBytes(alg));
            return verifier.verify(provided);
        } catch (SignatureException | IllegalArgumentException malformedSignature) { return false; }
    }

    public static PublicKey jwkPublicKey(JsonObject jwk) throws Exception {
        String kty = jwk.get("kty").getAsString();
        if ("RSA".equals(kty)) {
            BigInteger n = new BigInteger(1, b64(jwk.get("n").getAsString()));
            BigInteger e = new BigInteger(1, b64(jwk.get("e").getAsString()));
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }
        if ("EC".equals(kty)) {
            String crv = jwk.get("crv").getAsString();
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName(crv)));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(new BigInteger(1, b64(jwk.get("x").getAsString())), new BigInteger(1, b64(jwk.get("y").getAsString())));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
        }
        if ("OKP".equals(kty) && "Ed25519".equals(jwk.get("crv").getAsString())) {
            byte[] raw = b64(jwk.get("x").getAsString()); byte[] prefix = hex("302a300506032b6570032100");
            byte[] der = new byte[prefix.length + raw.length]; System.arraycopy(prefix,0,der,0,prefix.length); System.arraycopy(raw,0,der,prefix.length,raw.length);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        }
        throw new IllegalArgumentException("Unsupported JWKS key type: " + kty);
    }

    private static String signatureName(String alg) {
        if (alg.startsWith("RS")) return "SHA" + alg.substring(2) + "withRSA";
        if (alg.startsWith("PS")) return "RSASSA-PSS";
        if (alg.startsWith("ES")) return "SHA" + alg.substring(2) + "withECDSA";
        if ("EdDSA".equals(alg)) return "Ed25519";
        throw new IllegalArgumentException("Unsupported JWT algorithm: " + alg);
    }
    private static void setPssParameters(Signature s, String alg) throws InvalidAlgorithmParameterException {
        if (!alg.startsWith("PS")) return;
        String digest = "SHA-" + alg.substring(2);
        int size = Integer.parseInt(alg.substring(2)) / 8;
        s.setParameter(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), size, 1));
    }
    private static int curveBytes(String alg) { return alg.endsWith("256") ? 32 : alg.endsWith("384") ? 48 : 66; }
    private static byte[] hmac(String alg, byte[] key, byte[] message) throws Exception {
        String name = "HmacSHA" + alg.substring(2);
        Mac mac = Mac.getInstance(name); mac.init(new SecretKeySpec(key.length == 0 ? new byte[]{0} : key, name));
        if (key.length == 0) { // SecretKeySpec rejects an empty key; HMAC requires an actual zero-length key.
            int block = alg.endsWith("512") ? 128 : 64;
            MessageDigest digest = MessageDigest.getInstance("SHA-" + alg.substring(2));
            byte[] in = new byte[block], out = new byte[block];
            java.util.Arrays.fill(in,(byte)0x36); java.util.Arrays.fill(out,(byte)0x5c);
            digest.update(in); digest.update(message); byte[] inner = digest.digest();
            digest.update(out); digest.update(inner); return digest.digest();
        }
        return mac.doFinal(message);
    }
    private static byte[] derToJose(byte[] der, int width) {
        int p=0; if (der[p++]!=0x30) throw new IllegalArgumentException("Invalid ECDSA signature"); p=skipLength(der,p); if (der[p++]!=0x02) throw new IllegalArgumentException("Invalid ECDSA signature");
        int rl=der[p++]&255; byte[] r=java.util.Arrays.copyOfRange(der,p,p+rl); p+=rl; if(der[p++]!=0x02) throw new IllegalArgumentException("Invalid ECDSA signature");
        int sl=der[p++]&255; byte[] s=java.util.Arrays.copyOfRange(der,p,p+sl); byte[] raw=new byte[width*2]; copyInt(r,raw,0,width); copyInt(s,raw,width,width); return raw;
    }
    private static byte[] joseToDer(byte[] raw, int width) {
        if(raw.length!=width*2) throw new IllegalArgumentException("ECDSA signature length does not match curve");
        byte[] r=positiveInt(java.util.Arrays.copyOfRange(raw,0,width)), s=positiveInt(java.util.Arrays.copyOfRange(raw,width,width*2));
        int body=2+r.length+2+s.length; int headerBytes=body<128?2:3; byte[] out=new byte[headerBytes+body]; int i=0; out[i++]=0x30; if(body<128) out[i++]=(byte)body; else { out[i++]=(byte)0x81; out[i++]=(byte)body; } out[i++]=0x02; out[i++]=(byte)r.length; System.arraycopy(r,0,out,i,r.length); i+=r.length; out[i++]=0x02; out[i++]=(byte)s.length; System.arraycopy(s,0,out,i,s.length); return out;
    }
    private static int skipLength(byte[] der, int index) { int first=der[index++]&255; if(first<128) return index; int count=first&127; return index+count; }
    private static byte[] positiveInt(byte[] v) { int i=0; while(i<v.length-1 && v[i]==0) i++; boolean pad=(v[i]&0x80)!=0; byte[] out=new byte[v.length-i+(pad?1:0)]; System.arraycopy(v,i,out,pad?1:0,v.length-i); return out; }
    private static void copyInt(byte[] source, byte[] target, int offset, int width) { int start=source.length>width && source[0]==0?source.length-width:Math.max(0,source.length-width); int length=Math.min(width,source.length); System.arraycopy(source,start,target,offset+width-length,length); }
    private static String curveName(String c) { return switch(c) { case "P-256" -> "secp256r1"; case "P-384" -> "secp384r1"; case "P-521" -> "secp521r1"; default -> throw new IllegalArgumentException("Unsupported EC curve: "+c); }; }
    private static String[] parts(String token) { String[] p=token.trim().split("\\.",-1); if(p.length!=3) throw new IllegalArgumentException("Expected a three-segment JWT"); return p; }
    private static String decode(String s) { return new String(b64(s),StandardCharsets.UTF_8); }
    private static JsonObject object(String s) { return JsonParser.parseString(s).getAsJsonObject(); }
    private static byte[] b64(String s) { return Base64.getUrlDecoder().decode(pad(s)); }
    private static String pad(String s) { return s + "=".repeat((4-s.length()%4)%4); }
    private static String encode(String s) { return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }
    private static byte[] pemBytes(String pem) { return Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", "")); }
    private static byte[] hex(String s) { byte[] out=new byte[s.length()/2]; for(int i=0;i<out.length;i++) out[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16); return out; }
    private static byte[] unsigned(BigInteger n){byte[] b=n.toByteArray();return b.length>1&&b[0]==0?java.util.Arrays.copyOfRange(b,1,b.length):b;}
    private static byte[] fixed(BigInteger n,int length){byte[] raw=unsigned(n);byte[] out=new byte[length];System.arraycopy(raw,Math.max(0,raw.length-length),out,Math.max(0,length-raw.length),Math.min(raw.length,length));return out;}
    private static String b64url(byte[] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
}
