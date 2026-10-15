// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.attacker.model;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Explicitly started, stoppable local key-material server for controlled jku/x5u tests. */
public final class JwtKeyMaterialServer {
    private static final Gson JSON=new Gson();
    private HttpServer server;
    private String advertisedHost;
    private int port;

    public synchronized void start(String bindHost,String advertisedHost,int port,JsonObject jwk,byte[] certificate)throws Exception{
        stop();
        HttpServer candidate=HttpServer.create(new InetSocketAddress(bindHost,port),0);
        JsonObject document=new JsonObject();JsonArray keys=new JsonArray();keys.add(jwk);document.add("keys",keys);
        byte[] jwks=JSON.toJson(document).getBytes(StandardCharsets.UTF_8);
        String pem="-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(certificate)+"\n-----END CERTIFICATE-----\n";
        byte[] cert=pem.getBytes(StandardCharsets.US_ASCII);
        candidate.createContext("/jwks.json",exchange->respond(exchange,jwks,"application/json"));
        candidate.createContext("/cert.pem",exchange->respond(exchange,cert,"application/x-pem-file"));
        candidate.start();server=candidate;this.advertisedHost=advertisedHost;this.port=port;
    }
    private static void respond(com.sun.net.httpserver.HttpExchange exchange,byte[] body,String contentType)throws java.io.IOException{
        exchange.getResponseHeaders().set("Content-Type",contentType+"; charset=utf-8");exchange.getResponseHeaders().set("Cache-Control","no-store");
        exchange.sendResponseHeaders(200,body.length);try(var output=exchange.getResponseBody()){output.write(body);}
    }
    public synchronized boolean isRunning(){return server!=null;}
    public synchronized String jwksUrl(){return isRunning()?"http://"+advertisedHost+":"+port+"/jwks.json":"";}
    public synchronized String certificateUrl(){return isRunning()?"http://"+advertisedHost+":"+port+"/cert.pem":"";}
    public synchronized void stop(){if(server!=null){server.stop(0);server=null;}}
}
