package com.ad3bay0.crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECC {

    private Cipher cipher;
    public ECC() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        this.cipher = Cipher.getInstance("ECIESwithAES-CBC", "BC");
    }

    public ECPrivateKey getPrivate(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPrivateKey) kf.generatePrivate(spec);
    }

    public ECPublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(spec);
    }


    public String encryptText(String msg, ECPublicKey pubkey)
            throws
            IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, pubkey);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }

    public String decryptText(String msg, ECPrivateKey privkey)
            throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        this.cipher.init(Cipher.DECRYPT_MODE, privkey,this.cipher.getParameters());
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), StandardCharsets.UTF_8);
    }


    public static void main(String[] args) throws Exception {
        ECC ac = new ECC();
        ECPrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
        ECPublicKey publicKey = ac.getPublic("KeyPair/publicKey");

        String msg = "Hello world!";
        String encrypted_msg = ac.encryptText(msg,publicKey);
        System.out.println("encrypted "+encrypted_msg);
        String decrypted_msg = ac.decryptText(encrypted_msg, privateKey);
        System.out.println("Original Message: " + msg +
                "\nEncrypted Message: " + encrypted_msg
                + "\nDecrypted Message: " + decrypted_msg);
    }
}
