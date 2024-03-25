package com.mailer;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.javatuples.Pair;

import java.util.HashMap;
import java.util.regex.Pattern;


public class Challenge {

    private HashMap<String, Pair<String,Pair<byte[],byte[]>>> challenges = new HashMap<String, Pair<String,Pair<byte[],byte[]>>>();

    public static boolean patternMatches(String checkString, String regexPattern) {
        return Pattern.compile(regexPattern)
        .matcher(checkString)
        .matches();
    }

    public static boolean emailIsValid(String email) {
        String regexPattern = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        return patternMatches(email, regexPattern);
    }
    
    private void addChallenge(String mail, String challenge, byte[] p, byte[] p_pub) {
        challenges.put(mail, new Pair<String,Pair<byte[],byte[]>>(challenge,new Pair<byte[],byte[]>(p,p_pub)));
    }

    private void removeChallenge(String mail) {
        challenges.remove(mail);
    }

    private boolean hasChallenge(String mail) {
        return challenges.containsKey(mail);
    }
    
    public Pair<String,Pair<byte[],byte[]>> getChallenge(String mail) {
        return challenges.get(mail);
    }
    
    private static void sendChallenge(String user, String password, String destination, String challenge) {
        Properties properties = new Properties();
        
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", "smtp-mail.outlook.com");
        properties.put("mail.smtp.port", "587");
        Session session = Session.getInstance(properties, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(user, password);
            }
        });
        System.out.println("session.getProviders():" + session.getProviders()[0].getType());
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(user);
            message.addRecipient(Message.RecipientType.TO, new InternetAddress(destination));
            message.setSubject(String.format("[CODE] %s",challenge));
            message.setText(challenge);
            Transport.send(message);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
        System.out.println("Message sent");
    }
    
    public boolean verifyChallenge(String mail, String code) {
        return getChallenge(mail) != null && getChallenge(mail).getValue0().equals(code);
    }

    public void startChallenge(String id, String chall, byte[] p, byte[] p_pub) {
        if (hasChallenge(id)) {
            removeChallenge(id);
        }
        addChallenge(id, chall, p, p_pub);
        String username = "ecsqb_projet_crypto@outlook.fr";
        String password = "S8HL5f5Zggjh26";
        sendChallenge(username, password, id, getChallenge(id).getValue0());
    }
}