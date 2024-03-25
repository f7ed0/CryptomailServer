package com.mailer.poc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class TestGamal {
    private Element p;
    private Element s;
    private Element p_pub;
    private Pairing pairing;

    TestGamal() {
        this.pairing = PairingFactory.getPairing("./curves/a.properties");
        this.s = this.pairing.getZr().newRandomElement();
        this.p = this.pairing.getG1().newRandomElement();
        this.p_pub = this.p.duplicate().mulZn(s);
    }

    public void printParam() {
        System.out.println("g : "+Base64.getEncoder().encodeToString(this.p.toBytes()));
        System.out.println(this.p);
        System.out.println("h : "+Base64.getEncoder().encodeToString(this.p_pub.toBytes()));
        System.out.println(this.p_pub);
        System.out.println();
    }

    public byte[] decrypt(Element U, Element V) {
        Element up = U.duplicate().mulZn(s);

        return V.duplicate().sub(up).toBytes();
    }

    public static void main(String[] args) {
        TestGamal t = new TestGamal();
        t.printParam();
        Scanner sc = new Scanner(System.in);
        byte[] ub = Base64.getDecoder().decode(sc.nextLine());
        byte[] vb = Base64.getDecoder().decode(sc.nextLine());
        Pairing pairing = PairingFactory.getPairing("curves/a.properties");
        Element U = pairing.getG1().newElementFromBytes(ub);
        Element V = pairing.getG1().newElementFromBytes(vb);
        Element d_id = pairing.getG1().newElementFromBytes(t.decrypt(U, V));
        System.out.println(d_id.toString());
        sc.close();
    }
}
