package com.mailer;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;


import org.javatuples.Pair;

public class IBEServer {
    private Element s;
    private Element P;
    private Element P_pub;

    private Pairing pairing;
    private HttpServer server;
    private Challenge challenger;
    private final GsonBuilder json;
    

    IBEServer(String curvefile, String adress, int port) throws IOException {
        this.pairing = PairingFactory.getPairing(curvefile);
        this.generateParams();
        this.server = HttpServer.create(new InetSocketAddress(adress,port), 10);
        this.contextCreator();
        this.json = new GsonBuilder();
        this.challenger = new Challenge();
    }

    private void generateParams() {
        // s
        try {
            FileInputStream fis = new FileInputStream("./params/s.key");
            byte[] buffer = new byte[2048];
            int n = fis.read(buffer);
            if (n == 2048) {
                System.err.println("PARTIAL READ");
            }
            this.s = pairing.getZr().newElementFromBytes(buffer);
            fis.close();
        } catch (IOException e) {
            System.err.println("error : "+e.getMessage()+". cannot get params/s.key. creating a new one.");
            this.s = pairing.getZr().newRandomElement();
            try {
                FileOutputStream fos =  new FileOutputStream("./params/s.key");
                fos.write(this.s.toBytes());
                fos.close();
            } catch (IOException err) {
                System.err.println("error : "+err.getMessage()+". s will not be saved.");
            }
        }
        
        // P
        try {
            FileInputStream fis = new FileInputStream("./params/P.key");
            byte[] buffer = new byte[2048];
            int n = fis.read(buffer);
            if (n == 2048) {
                System.err.println("PARTIAL READ");
            }
            this.P = pairing.getG1().newElementFromBytes(buffer);
            fis.close();
        } catch (IOException e) {
            System.err.println("error : "+e.getMessage()+". cannot get params/P.key. creating a new one.");
            this.P = pairing.getG1().newRandomElement();
            try {
                FileOutputStream fos =  new FileOutputStream("./params/P.key");
                fos.write(this.P.toBytes());
                fos.close();
            } catch (IOException err) {
                System.err.println("error : "+err.getMessage()+". s will not be saved.");
            }    
        }

        
        this.P_pub = this.P.duplicate().mulZn(this.s);

        System.out.println("# GOING WITH");
        System.out.println("# P\t: "+this.P.toString());
        System.out.println("# P_pub\t: "+this.P_pub.toString());
        System.out.println("# s\t: "+this.s.toString());
    }

    static public String base64it(byte[] arr) {
        return Base64.getEncoder().encodeToString(arr);
    }

    private void contextCreator() {
        IBEServer ibe = this;
        this.server.createContext("/params", new HttpHandler() {
            public void handle(HttpExchange he) throws IOException {
                try {
                    System.out.print(he.getRequestMethod()+" : /params");
                    StringBuilder sb = new StringBuilder();
                    sb.append("{\n\t'P'\t: '");
                    sb.append(IBEServer.base64it(ibe.P.toBytes()));
                    sb.append("',\n");
                    sb.append("\t'Ppub'\t: '"+IBEServer.base64it(ibe.P_pub.toBytes())+"',");
                    sb.append("\n\t'H1'\t: 'jpbc fromHash()'");
                    sb.append("\n\t'H2'\t: 'toByte() + SHA512'");
                    sb.append("\n}");
                    byte[] bytes = sb.toString().getBytes();
                    he.getResponseHeaders().set("content-type","application/json");
                    he.sendResponseHeaders(200, bytes.length);
                    OutputStream os = he.getResponseBody();
                    os.write(bytes);
                    os.close();
                    System.out.println("\t->\t200");
                } catch(Exception e) {
                    System.out.println(e.toString());
                }
            }
        });
        this.server.createContext("/ask", new HttpHandler() {
            public void handle(HttpExchange he) throws IOException {
                try {
                    System.out.print(he.getRequestMethod()+" : /ask");
                    // TODO check public key
                    byte[] bytes = he.getRequestBody().readAllBytes();
                    
                    final Gson gson = json.create();
                    JsonObject res = gson.fromJson(new String(bytes, StandardCharsets.UTF_8), JsonObject.class );
                    String id = res.get("id").getAsString();
                    String p_str = res.get("g").getAsString();
                    String p_pub_str = res.get("h").getAsString();
                    System.out.println(p_str);
                    System.out.println(p_pub_str);
                    if (!Challenge.emailIsValid(id)) {
                        byte[] buffer = ("{\n\t'error' : 'INVALID MAIL'\n}").getBytes("UTF-8");
                        he.getResponseHeaders().set("content-type","application/json");
                        he.sendResponseHeaders(400, buffer.length);
                        he.getResponseBody().write(buffer);
                        he.getResponseBody().close();
                        System.out.println("\t->\t400");
                        return;
                    }
                    byte[] pb_str = Base64.getDecoder().decode(p_str);
                    byte[] pb_pub_str = Base64.getDecoder().decode(p_pub_str);
                    challenger.startChallenge(id, IBEServer.base64it(Arrays.copyOfRange(pairing.getG1().newRandomElement().toBytes(),0,10)) , pb_str , pb_pub_str );
                    
                    he.sendResponseHeaders(204, -1);
                    System.out.println("\t->\t204");
                    he.getResponseBody().close();
                } catch(Exception e) {
                    System.out.println(e.toString());
                }
            }
        });

        this.server.createContext("/chall", new HttpHandler() {
            public void handle(HttpExchange he) throws IOException {
                System.out.println(he.getRequestMethod()+" : /chall ---------------------------");
                byte[] bytes = he.getRequestBody().readAllBytes();
                final Gson gson = json.create();
                JsonObject res = gson.fromJson(new String(bytes, StandardCharsets.UTF_8), JsonObject.class );
                String id = res.get("id").getAsString();
                String key = res.get("key").getAsString();
                if (!challenger.verifyChallenge(id, key)) {
                    byte[] buffer = ("{\n\t'error' : 'INVALID KEY FOR THIS MAIL'\n}").getBytes("UTF-8");
                    he.getResponseHeaders().set("content-type","application/json");
                    he.sendResponseHeaders(400, buffer.length);
                    he.getResponseBody().write(buffer);
                    he.getResponseBody().close();
                    return;
                }
                Pair<byte[],byte[]> pair = challenger.getChallenge(id).getValue1();
                Element Q_id = ibe.generate_QID(id.getBytes());
                Element D_id = ibe.generate_DID(Q_id);
                System.out.println("QID #####################################");
                System.out.println(Q_id.toString());
                System.out.println("DID #####################################");
                System.out.println(D_id.toString());
                Element P = pairing.getG1().newElementFromBytes(pair.getValue0());
                Element P_pub = pairing.getG1().newElementFromBytes(pair.getValue1());
                Pair<byte[],byte[]> gamal = elGamalCrypt(P, P_pub, D_id, Q_id);
                byte[] buffer = ("{\n\t'encr_U' : '"+IBEServer.base64it(gamal.getValue0())+"'\n\t'encr_V' : '"+IBEServer.base64it(gamal.getValue1())+"'\n}").getBytes("UTF-8");
                he.getResponseHeaders().set("content-type","application/json");
                he.sendResponseHeaders(200, buffer.length);
                System.out.println("\t->\t200");
                he.getResponseBody().write(buffer);
                he.sendResponseHeaders(200, buffer.length);
                he.getResponseBody().close();
                System.out.println("----------------------------------------");
                return;
            }
        });
    }

    public Element H1(byte[] e) {
        return this.pairing.getG1().newElementFromHash(e, 0, e.length);
    }

    public byte[] H2(Element e) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA512");
            digest.update(e.toBytes());
            return digest.digest();
        } catch (NoSuchAlgorithmException err) {
            System.err.println("SHA512 NOT FOUND");
            return null;
        }
    }

    public Pair<byte[],byte[]> elGamalCrypt(Element g, Element h, Element message, Element qid ) {
        System.out.println("g #####################################");
        System.out.println(g);
        System.out.println("h #####################################");
        System.out.println(h);
        System.out.println("#######################################");
        Element r = this.pairing.getZr().newRandomElement();
        Element U = g.duplicate().mulZn(r);
        Element V = h.duplicate().mulZn(r);
        V.add(message);

        return new Pair<byte[],byte[]>(U.toBytes(),V.toBytes());
    }

    public Element generate_QID(byte[] id) {
        return H1(id);
    }

    public Element generate_DID(Element QID) {
        Element DID = QID.duplicate().mulZn(this.s);
        return DID;
    }


    public static void main(String[] args) throws Exception {
        try {
            IBEServer server = new IBEServer("./curves/a.properties","0.0.0.0",80);
            System.out.println(server);
            System.out.println("=======  SERVER STARTED  =======");
            server.server.start();
        } catch(IOException e) {
            System.err.println("Erreur lors de l'initialisation du sevreur.");
            System.err.println(e.getMessage());
            System.exit(1);
        }
        
        //while(true);
        
    }
}