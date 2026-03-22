package org.conscrypt;

import javax.net.ssl.SSLSession;

/* loaded from: classes3.dex */
public interface ConscryptHostnameVerifier {
    boolean verify(String str, SSLSession sSLSession);
}
