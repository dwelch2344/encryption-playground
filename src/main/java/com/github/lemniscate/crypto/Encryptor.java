package com.github.lemniscate.crypto;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Encryptor {

    public static final int DEFAULT_KEY_SIZE = 128;

    private int keySize;
    private Cipher pkCipher, aesCipher;
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;

    public Encryptor(int keySize) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        pkCipher = Cipher.getInstance("RSA");
        aesCipher = Cipher.getInstance("AES");
        this.keySize = keySize;

        aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
    }

    public void generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(keySize);
        SecretKey key = kgen.generateKey();
        aesKey = key.getEncoded();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }



    /**
     * Encrypts and then copies the contents of a given file.
     */
    public static void encrypt(File in, File out) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Encryptor e = new Encryptor(DEFAULT_KEY_SIZE);


        FileInputStream is = new FileInputStream(in);
        CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), aesCipher);

        copy(is, os);

        os.close();
    }

}
