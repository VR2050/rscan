package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import p005b.p199l.p200a.p201a.p248o1.C2323o;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;

/* renamed from: b.l.a.a.k1.m0.d */
/* loaded from: classes.dex */
public class C2161d implements InterfaceC2321m {

    /* renamed from: a */
    public final InterfaceC2321m f4859a;

    /* renamed from: b */
    public final byte[] f4860b;

    /* renamed from: c */
    public final byte[] f4861c;

    /* renamed from: d */
    @Nullable
    public CipherInputStream f4862d;

    public C2161d(InterfaceC2321m interfaceC2321m, byte[] bArr, byte[] bArr2) {
        this.f4859a = interfaceC2321m;
        this.f4860b = bArr;
        this.f4861c = bArr2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public final void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f4859a.addTransferListener(interfaceC2291f0);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        if (this.f4862d != null) {
            this.f4862d = null;
            this.f4859a.close();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public final Map<String, List<String>> getResponseHeaders() {
        return this.f4859a.getResponseHeaders();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public final Uri getUri() {
        return this.f4859a.getUri();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public final long open(C2324p c2324p) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            try {
                cipher.init(2, new SecretKeySpec(this.f4860b, "AES"), new IvParameterSpec(this.f4861c));
                C2323o c2323o = new C2323o(this.f4859a, c2324p);
                this.f4862d = new CipherInputStream(c2323o, cipher);
                if (c2323o.f5930g) {
                    return -1L;
                }
                c2323o.f5927c.open(c2323o.f5928e);
                c2323o.f5930g = true;
                return -1L;
            } catch (InvalidAlgorithmParameterException | InvalidKeyException e2) {
                throw new RuntimeException(e2);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e3) {
            throw new RuntimeException(e3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public final int read(byte[] bArr, int i2, int i3) {
        Objects.requireNonNull(this.f4862d);
        int read = this.f4862d.read(bArr, i2, i3);
        if (read < 0) {
            return -1;
        }
        return read;
    }
}
