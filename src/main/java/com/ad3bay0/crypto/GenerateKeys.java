package com.ad3bay0.crypto;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;

public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;


    public GenerateKeys() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        this.keyGen.initialize(spec, new SecureRandom());
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = (ECPrivateKey) pair.getPrivate();
        this.publicKey = (ECPublicKey) pair.getPublic();
    }

    public ECPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }


    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }


    public static void main(String[] args) throws Exception {
        GenerateKeys gk;
        try {
            gk = new GenerateKeys();
            gk.createKeys();
            gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
            gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.err.println(e.getMessage());
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }

    }
}
