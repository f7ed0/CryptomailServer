package com.mailer.poc;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author imino
 */
public class TestAes {
    

    public static void main(String[] args)
{
        try {
            final String secretKey = "voici la clé de secrète!!!!";
            Scanner sc = new Scanner(System.in);
            System.out.println("entrer un fichier à chiffrer:");
            String originalString = sc.nextLine();
            sc.close();

            File f = new File(originalString);

            byte[] buff;

            try {
                FileInputStream fis = new FileInputStream(f);
                buff = fis.readAllBytes();
                fis.close();
            } catch( Exception e) {
                System.err.println(e.getMessage());
                return;
            }

            
            String encryptedString = new String(AESCrypto.encrypt(buff, secretKey.getBytes("UTF-8"))) ;

            f = new File(originalString+".enc");

            try {
                FileOutputStream fos = new FileOutputStream(f);
                fos.write(encryptedString.getBytes("UTF-8"));
                fos.close();
            } catch( Exception e) {
                System.err.println(e.getMessage());
                return;
            }

            String decryptedString = AESCrypto.decrypt(encryptedString.getBytes("UTF-8"), secretKey.getBytes()) ;

            

            System.out.println(new String(buff));
            System.out.println(encryptedString);
            System.out.println(decryptedString);
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(TestAes.class.getName()).log(Level.SEVERE, null, ex);
        } 
}
    

}