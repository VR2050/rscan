package org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.conscrypt.NativeRef;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public final class OpenSSLECDHKeyAgreement extends KeyAgreementSpi {
    private int mExpectedResultLength;
    private OpenSSLKey mOpenSslPrivateKey;
    private byte[] mResult;

    private void checkCompleted() {
        if (this.mResult == null) {
            throw new IllegalStateException("Key agreement not completed");
        }
    }

    @Override // javax.crypto.KeyAgreementSpi
    public Key engineDoPhase(Key key, boolean z) {
        if (this.mOpenSslPrivateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (!z) {
            throw new IllegalStateException("ECDH only has one phase");
        }
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if (!(key instanceof PublicKey)) {
            StringBuilder m586H = C1499a.m586H("Not a public key: ");
            m586H.append(key.getClass());
            throw new InvalidKeyException(m586H.toString());
        }
        OpenSSLKey fromPublicKey = OpenSSLKey.fromPublicKey((PublicKey) key);
        byte[] bArr = new byte[this.mExpectedResultLength];
        int ECDH_compute_key = NativeCrypto.ECDH_compute_key(bArr, 0, fromPublicKey.getNativeRef(), this.mOpenSslPrivateKey.getNativeRef());
        if (ECDH_compute_key == -1) {
            throw new RuntimeException(C1499a.m626l("Engine returned ", ECDH_compute_key));
        }
        int i2 = this.mExpectedResultLength;
        if (ECDH_compute_key != i2) {
            if (ECDH_compute_key >= i2) {
                StringBuilder m586H2 = C1499a.m586H("Engine produced a longer than expected result. Expected: ");
                m586H2.append(this.mExpectedResultLength);
                m586H2.append(", actual: ");
                m586H2.append(ECDH_compute_key);
                throw new RuntimeException(m586H2.toString());
            }
            byte[] bArr2 = this.mResult;
            System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
            bArr = new byte[ECDH_compute_key];
        }
        this.mResult = bArr;
        return null;
    }

    @Override // javax.crypto.KeyAgreementSpi
    public int engineGenerateSecret(byte[] bArr, int i2) {
        checkCompleted();
        int length = bArr.length - i2;
        byte[] bArr2 = this.mResult;
        if (bArr2.length <= length) {
            System.arraycopy(bArr2, 0, bArr, i2, bArr2.length);
            return this.mResult.length;
        }
        StringBuilder m586H = C1499a.m586H("Needed: ");
        m586H.append(this.mResult.length);
        m586H.append(", available: ");
        m586H.append(length);
        throw new ShortBufferException(m586H.toString());
    }

    @Override // javax.crypto.KeyAgreementSpi
    public void engineInit(Key key, SecureRandom secureRandom) {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if (!(key instanceof PrivateKey)) {
            StringBuilder m586H = C1499a.m586H("Not a private key: ");
            m586H.append(key.getClass());
            throw new InvalidKeyException(m586H.toString());
        }
        OpenSSLKey fromPrivateKey = OpenSSLKey.fromPrivateKey((PrivateKey) key);
        this.mExpectedResultLength = (NativeCrypto.EC_GROUP_get_degree(new NativeRef.EC_GROUP(NativeCrypto.EC_KEY_get1_group(fromPrivateKey.getNativeRef()))) + 7) / 8;
        this.mOpenSslPrivateKey = fromPrivateKey;
    }

    @Override // javax.crypto.KeyAgreementSpi
    public byte[] engineGenerateSecret() {
        checkCompleted();
        return this.mResult;
    }

    @Override // javax.crypto.KeyAgreementSpi
    public SecretKey engineGenerateSecret(String str) {
        checkCompleted();
        return new SecretKeySpec(engineGenerateSecret(), str);
    }

    @Override // javax.crypto.KeyAgreementSpi
    public void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) {
        if (algorithmParameterSpec == null) {
            engineInit(key, secureRandom);
            return;
        }
        throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
    }
}
