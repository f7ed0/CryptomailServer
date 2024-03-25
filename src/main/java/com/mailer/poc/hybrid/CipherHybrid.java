package com.mailer.poc.hybrid;

import it.unisa.dia.gas.jpbc.Element;

public class CipherHybrid {
    public Element U;
    public byte[] V;
    public byte[] messageCipher;

    CipherHybrid(Element U, byte[] V, byte[] messageCipher) {
        this.U = U;
        this.V = V;
        this.messageCipher = messageCipher;
    }
}
