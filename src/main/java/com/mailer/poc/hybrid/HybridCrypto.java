package com.mailer.poc.hybrid;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class HybridCrypto {
    private Element privateKey;
    private Element P;
    private Element Ppub;
    private Field G1;
    private Field Zr;

    HybridCrypto(Element P, Element Ppub) {
        this.privateKey = null;
        this.P = P.duplicate();
        this.Ppub = Ppub.duplicate();
        Pairing pairing = PairingFactory.getPairing("./curves/a.properties");
        this.G1 = pairing.getG1();
        this.Zr = pairing.getZr();
    }



    public void setPrivateKey(Element pk) {
        this.privateKey = pk;
    }

    public Element H1(byte[] e) {
        return this.G1.newElementFromHash(e, 0, e.length);
    }

    public byte[] H2(Element e) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA512");
            digest.update(e.toBytes());
            return Arrays.copyOf(digest.digest(),16);
        } catch (NoSuchAlgorithmException err) {
            System.err.println("SHA512 NOT FOUND");
            return null;
        }
    }

    public static byte[] XOR(byte[] a, byte[] b) {
        byte[] res = new byte[16];
        for (int i = 0 ; i < 16 ; i++) {
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }

    public CipherHybrid encrypt(String id, byte[] content) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Element r = this.Zr.newRandomElement();
        Element U = this.P.duplicate().mulZn(r);
        Element Qid = H1(id.getBytes());
        byte[] AesKey = Arrays.copyOf(this.G1.newRandomElement().toBytes(),16);
        byte[] V = XOR(AesKey,H2(Qid.duplicate().mul(Ppub).powZn(r)));
        Cipher cipher= Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keyspec=new SecretKeySpec(AesKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keyspec);
        byte[] ciphertext=Base64.getEncoder().encode(cipher.doFinal(content));
        System.out.println("Key was : "+Base64.getEncoder().encodeToString(AesKey));
        return new CipherHybrid(U, V, ciphertext);
    }

    public byte[] decrypt(CipherHybrid cipherText) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoPrivateKeyException {
        byte[] AesKey = Arrays.copyOf(XOR(cipherText.V, H2(privateKey.duplicate().mul(cipherText.U))),16);
        Cipher cipher= Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keyspec = new SecretKeySpec(AesKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keyspec);
        System.out.println("Key was : "+Base64.getEncoder().encodeToString(AesKey));
        return cipher.doFinal(Base64.getDecoder().decode(cipherText.messageCipher));
    }

    

    public static void main(String[] args) {
        Pairing pairing = PairingFactory.getPairing("./curves/a.properties");

        Element s =  pairing.getZr().newRandomElement();
        Element P =  pairing.getG1().newRandomElement();
        Element Ppub =  P.duplicate().mulZn(s);

        HybridCrypto c = new HybridCrypto(P, Ppub);
        c.setPrivateKey(c.H1("abcdef".getBytes()).mulZn(s));

        
        
        try {
            FileInputStream fis = new FileInputStream("test_img.png");
            CipherHybrid cipher =  c.encrypt("abcdef", fis.readAllBytes());
            FileOutputStream fos = new FileOutputStream("test_img.png.enc");
            fos.write(cipher.messageCipher);
            fos.close();
            fos = new FileOutputStream("test_img.png.u.key");
            fos.write(cipher.U.toBytes());
            fos.close();
            fos = new FileOutputStream("test_img.png.v.key");
            fos.write(cipher.V);
            fos.close();
            fis.close();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

        

        try {
            FileInputStream fis = new FileInputStream("test_img.png.enc");
            byte[] img = fis.readAllBytes();
            fis.close();
            fis = new FileInputStream("test_img.png.u.key");
            Element U = pairing.getG1().newElementFromBytes(fis.readAllBytes());
            fis.close();
            fis = new FileInputStream("test_img.png.v.key");
            byte[] V = fis.readAllBytes();
            fis.close();
            CipherHybrid nc = new CipherHybrid(U,V,img);
            FileOutputStream fos = new FileOutputStream("test_img.png.decr.png");
            fos.write(c.decrypt(nc));
            fos.close();
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
