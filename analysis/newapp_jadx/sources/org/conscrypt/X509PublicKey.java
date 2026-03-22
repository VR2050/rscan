package org.conscrypt;

import java.security.PublicKey;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public final class X509PublicKey implements PublicKey {
    private static final long serialVersionUID = -8610156854731664298L;
    private final String algorithm;
    private final byte[] encoded;

    public X509PublicKey(String str, byte[] bArr) {
        this.algorithm = str;
        this.encoded = bArr;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || X509PublicKey.class != obj.getClass()) {
            return false;
        }
        X509PublicKey x509PublicKey = (X509PublicKey) obj;
        String str = this.algorithm;
        if (str == null) {
            if (x509PublicKey.algorithm != null) {
                return false;
            }
        } else if (!str.equals(x509PublicKey.algorithm)) {
            return false;
        }
        return Arrays.equals(this.encoded, x509PublicKey.encoded);
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return this.encoded;
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    public int hashCode() {
        String str = this.algorithm;
        return Arrays.hashCode(this.encoded) + (((str == null ? 0 : str.hashCode()) + 31) * 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("X509PublicKey [algorithm=");
        m586H.append(this.algorithm);
        m586H.append(", encoded=");
        m586H.append(Arrays.toString(this.encoded));
        m586H.append("]");
        return m586H.toString();
    }
}
