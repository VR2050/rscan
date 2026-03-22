package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import javax.crypto.NoSuchPaddingException;
import org.conscrypt.OpenSSLCipher;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public abstract class OpenSSLEvpCipherDESEDE extends OpenSSLEvpCipher {
    private static final int DES_BLOCK_SIZE = 8;

    /* renamed from: org.conscrypt.OpenSSLEvpCipherDESEDE$1 */
    public static /* synthetic */ class C50591 {
        public static final /* synthetic */ int[] $SwitchMap$org$conscrypt$OpenSSLCipher$Padding;

        static {
            OpenSSLCipher.Padding.values();
            int[] iArr = new int[3];
            $SwitchMap$org$conscrypt$OpenSSLCipher$Padding = iArr;
            try {
                iArr[OpenSSLCipher.Padding.NOPADDING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$conscrypt$OpenSSLCipher$Padding[OpenSSLCipher.Padding.PKCS5PADDING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    public static class CBC extends OpenSSLEvpCipherDESEDE {

        public static class NoPadding extends CBC {
            public NoPadding() {
                super(OpenSSLCipher.Padding.NOPADDING);
            }
        }

        public static class PKCS5Padding extends CBC {
            public PKCS5Padding() {
                super(OpenSSLCipher.Padding.PKCS5PADDING);
            }
        }

        public CBC(OpenSSLCipher.Padding padding) {
            super(OpenSSLCipher.Mode.CBC, padding);
        }
    }

    public OpenSSLEvpCipherDESEDE(OpenSSLCipher.Mode mode, OpenSSLCipher.Padding padding) {
        super(mode, padding);
    }

    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedKeySize(int i2) {
        if (i2 != 16 && i2 != 24) {
            throw new InvalidKeyException("key size must be 128 or 192 bits");
        }
    }

    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedMode(OpenSSLCipher.Mode mode) {
        if (mode == OpenSSLCipher.Mode.CBC) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("Unsupported mode ");
        m586H.append(mode.toString());
        throw new NoSuchAlgorithmException(m586H.toString());
    }

    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedPadding(OpenSSLCipher.Padding padding) {
        int ordinal = padding.ordinal();
        if (ordinal == 0 || ordinal == 1) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("Unsupported padding ");
        m586H.append(padding.toString());
        throw new NoSuchPaddingException(m586H.toString());
    }

    @Override // org.conscrypt.OpenSSLCipher
    public String getBaseCipherName() {
        return "DESede";
    }

    @Override // org.conscrypt.OpenSSLCipher
    public int getCipherBlockSize() {
        return 8;
    }

    @Override // org.conscrypt.OpenSSLEvpCipher
    public String getCipherName(int i2, OpenSSLCipher.Mode mode) {
        StringBuilder m590L = C1499a.m590L(i2 == 16 ? "des-ede" : "des-ede3", "-");
        m590L.append(mode.toString().toLowerCase(Locale.US));
        return m590L.toString();
    }
}
