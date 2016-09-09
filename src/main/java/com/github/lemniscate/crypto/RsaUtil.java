package com.github.lemniscate.crypto;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by dave on 9/8/16.
 */
// See FileEncryptionTest
public class RsaUtil {

    public String loadStrippedDataFromFile(String filePath) throws IOException {
        return loadStrippedDataFromFile(new File(filePath));
    }

    public String loadStrippedDataFromFile(File file) throws IOException {
        List<String> lines = Files.readAllLines(file.toPath());
        lines.remove(0);
        lines.remove(lines.size() - 1);
        return lines.stream()
                    .collect(Collectors.joining())
                    .replace("\\s", "");
    }

    public RSAPrivateKeySpec generatePrivateKeySpec(String base64keyData) throws IOException {
        return generatePrivateKeySpec(Base64.getDecoder().decode(base64keyData));
    }

    public RSAPrivateKeySpec generatePrivateKeySpec(byte[] bytes) throws IOException {
        DerInputStream derReader = new DerInputStream(bytes);

        DerValue[] seq = derReader.getSequence(0);

        if (seq.length < 9) {
            throw new RuntimeException("Could not parse a PKCS1 private key.");
        }

        // skip version seq[0];
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        return keySpec;
    }

    public RSAPrivateCrtKey generatePrivateKey(String base64encoded) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        RSAPrivateKeySpec spec = generatePrivateKeySpec(Base64.getDecoder().decode(base64encoded));
        return generatePrivateKey(spec);
    }

    public RSAPrivateCrtKey generatePrivateKey(RSAPrivateKeySpec keySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        PrivateKey privKey = factory.generatePrivate(keySpec);
        RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) privKey;
        return rsaPrivate;
    }

    public RSAPublicKey generatePublicKey(RSAPrivateCrtKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey generatedPublic = keyFactory.generatePublic(publicKeySpec);
        return (RSAPublicKey) generatedPublic;
    }


    public String encrypt(String rawText, PublicKey publicKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return org.apache.commons.codec.binary.Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }

    public String decrypt(String cipherText, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(org.apache.commons.codec.binary.Base64.decodeBase64(cipherText)), "UTF-8");
    }

}
