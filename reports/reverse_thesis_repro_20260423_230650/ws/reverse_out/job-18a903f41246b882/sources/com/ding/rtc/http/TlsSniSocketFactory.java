package com.ding.rtc.http;

import android.net.SSLCertificateSocketFactory;
import android.util.Log;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/* JADX INFO: loaded from: classes.dex */
public class TlsSniSocketFactory extends SSLSocketFactory {
    private static final String TAG = "TlsSniSocketFactory";
    private final HttpsURLConnection mHttpsURLConnection;

    public TlsSniSocketFactory(HttpsURLConnection httpsURLConnection) {
        this.mHttpsURLConnection = httpsURLConnection;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket() throws IOException {
        return null;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port) throws IOException {
        return null;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return null;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return null;
    }

    @Override // javax.net.SocketFactory
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return null;
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getDefaultCipherSuites() {
        return new String[0];
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    @Override // javax.net.ssl.SSLSocketFactory
    public Socket createSocket(Socket plainSocket, String host, int port, boolean autoClose) throws IOException {
        String peerHost = this.mHttpsURLConnection.getRequestProperty("Host");
        if (peerHost == null) {
            peerHost = host;
        }
        Log.i(TAG, "customized createSocket. host: " + peerHost);
        InetAddress address = plainSocket.getInetAddress();
        if (autoClose) {
            plainSocket.close();
        }
        SSLCertificateSocketFactory sslSocketFactory = (SSLCertificateSocketFactory) SSLCertificateSocketFactory.getDefault(0);
        SSLSocket ssl = (SSLSocket) sslSocketFactory.createSocket(address, port);
        ssl.setEnabledProtocols(ssl.getSupportedProtocols());
        Log.i(TAG, "Setting SNI hostname");
        sslSocketFactory.setHostname(ssl, peerHost);
        SSLSession session = ssl.getSession();
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(peerHost, session)) {
            Log.w(TAG, "Cannot verify hostname: " + peerHost);
            throw new SSLPeerUnverifiedException("Cannot verify hostname: " + peerHost);
        }
        Log.i(TAG, "Established " + session.getProtocol() + " connection with " + session.getPeerHost() + " using " + session.getCipherSuite());
        return ssl;
    }
}
