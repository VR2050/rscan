package com.bjz.comm.net.factory;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$SSLSocketClient$bFsnYzvs6D40JPrXmtfsj_Z7IHM.class})
public class SSLSocketClient {
    public static SSLSocketFactory getSSLSocketFactory() {
        try {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, getTrustManager(), new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static TrustManager[] getTrustManager() {
        TrustManager[] trustAllCerts = {new X509TrustManager() { // from class: com.bjz.comm.net.factory.SSLSocketClient.1
            @Override // javax.net.ssl.X509TrustManager
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override // javax.net.ssl.X509TrustManager
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override // javax.net.ssl.X509TrustManager
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        return trustAllCerts;
    }

    public static HostnameVerifier getHostnameVerifier() {
        HostnameVerifier hostnameVerifier = new HostnameVerifier() { // from class: com.bjz.comm.net.factory.-$$Lambda$SSLSocketClient$bFsnYzvs6D40JPrXmtfsj_Z7IHM
            @Override // javax.net.ssl.HostnameVerifier
            public final boolean verify(String str, SSLSession sSLSession) {
                return SSLSocketClient.lambda$getHostnameVerifier$0(str, sSLSession);
            }
        };
        return hostnameVerifier;
    }

    static /* synthetic */ boolean lambda$getHostnameVerifier$0(String s, SSLSession sslSession) {
        return true;
    }
}
