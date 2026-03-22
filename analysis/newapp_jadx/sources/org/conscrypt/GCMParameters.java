package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public final class GCMParameters extends AlgorithmParametersSpi {
    private static final int DEFAULT_TLEN = 96;

    /* renamed from: iv */
    private byte[] f12987iv;
    private int tLen;

    public GCMParameters() {
    }

    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded() {
        long j2;
        long j3;
        long j4 = 0;
        try {
            j2 = NativeCrypto.asn1_write_init();
            try {
                j4 = NativeCrypto.asn1_write_sequence(j2);
                NativeCrypto.asn1_write_octetstring(j4, this.f12987iv);
                if (this.tLen != 96) {
                    NativeCrypto.asn1_write_uint64(j4, r4 / 8);
                }
                byte[] asn1_write_finish = NativeCrypto.asn1_write_finish(j2);
                NativeCrypto.asn1_write_free(j4);
                NativeCrypto.asn1_write_free(j2);
                return asn1_write_finish;
            } catch (IOException e2) {
                e = e2;
                long j5 = j4;
                j4 = j2;
                j3 = j5;
                try {
                    NativeCrypto.asn1_write_cleanup(j4);
                    throw e;
                } catch (Throwable th) {
                    th = th;
                    long j6 = j4;
                    j4 = j3;
                    j2 = j6;
                    NativeCrypto.asn1_write_free(j4);
                    NativeCrypto.asn1_write_free(j2);
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
                NativeCrypto.asn1_write_free(j4);
                NativeCrypto.asn1_write_free(j2);
                throw th;
            }
        } catch (IOException e3) {
            e = e3;
            j3 = 0;
        } catch (Throwable th3) {
            th = th3;
            j2 = 0;
        }
    }

    @Override // java.security.AlgorithmParametersSpi
    public <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> cls) {
        if (cls == null || !cls.getName().equals("javax.crypto.spec.GCMParameterSpec")) {
            throw new InvalidParameterSpecException(C1499a.m635u("Unsupported class: ", cls));
        }
        return cls.cast(Platform.toGCMParameterSpec(this.tLen, this.f12987iv));
    }

    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec) {
        GCMParameters fromGCMParameterSpec = Platform.fromGCMParameterSpec(algorithmParameterSpec);
        if (fromGCMParameterSpec == null) {
            throw new InvalidParameterSpecException("Only GCMParameterSpec is supported");
        }
        this.tLen = fromGCMParameterSpec.tLen;
        this.f12987iv = fromGCMParameterSpec.f12987iv;
    }

    @Override // java.security.AlgorithmParametersSpi
    public String engineToString() {
        return "Conscrypt GCM AlgorithmParameters";
    }

    public byte[] getIV() {
        return this.f12987iv;
    }

    public int getTLen() {
        return this.tLen;
    }

    public GCMParameters(int i2, byte[] bArr) {
        this.tLen = i2;
        this.f12987iv = bArr;
    }

    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bArr) {
        long j2;
        try {
            j2 = NativeCrypto.asn1_read_init(bArr);
            try {
                long asn1_read_sequence = NativeCrypto.asn1_read_sequence(j2);
                byte[] asn1_read_octetstring = NativeCrypto.asn1_read_octetstring(asn1_read_sequence);
                int asn1_read_uint64 = NativeCrypto.asn1_read_is_empty(asn1_read_sequence) ? 96 : ((int) NativeCrypto.asn1_read_uint64(asn1_read_sequence)) * 8;
                if (NativeCrypto.asn1_read_is_empty(asn1_read_sequence) && NativeCrypto.asn1_read_is_empty(j2)) {
                    this.f12987iv = asn1_read_octetstring;
                    this.tLen = asn1_read_uint64;
                    NativeCrypto.asn1_read_free(asn1_read_sequence);
                    NativeCrypto.asn1_read_free(j2);
                    return;
                }
                throw new IOException("Error reading ASN.1 encoding");
            } catch (Throwable th) {
                th = th;
                NativeCrypto.asn1_read_free(0L);
                NativeCrypto.asn1_read_free(j2);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            j2 = 0;
        }
    }

    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded(String str) {
        if (str != null && !str.equals("ASN.1")) {
            throw new IOException(C1499a.m637w("Unsupported format: ", str));
        }
        return engineGetEncoded();
    }

    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bArr, String str) {
        if (str != null && !str.equals("ASN.1")) {
            throw new IOException(C1499a.m637w("Unsupported format: ", str));
        }
        engineInit(bArr);
    }
}
