package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import android.util.Base64;
import androidx.annotation.Nullable;
import java.net.URLDecoder;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.o1.j */
/* loaded from: classes.dex */
public final class C2318j extends AbstractC2294h {

    /* renamed from: a */
    @Nullable
    public C2324p f5922a;

    /* renamed from: b */
    @Nullable
    public byte[] f5923b;

    /* renamed from: c */
    public int f5924c;

    /* renamed from: d */
    public int f5925d;

    public C2318j() {
        super(false);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        if (this.f5923b != null) {
            this.f5923b = null;
            transferEnded();
        }
        this.f5922a = null;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        C2324p c2324p = this.f5922a;
        if (c2324p != null) {
            return c2324p.f5933a;
        }
        return null;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        transferInitializing(c2324p);
        this.f5922a = c2324p;
        this.f5925d = (int) c2324p.f5938f;
        Uri uri = c2324p.f5933a;
        String scheme = uri.getScheme();
        if (!"data".equals(scheme)) {
            throw new C2205l0(C1499a.m637w("Unsupported scheme: ", scheme));
        }
        String[] m2316H = C2344d0.m2316H(uri.getSchemeSpecificPart(), ChineseToPinyinResource.Field.COMMA);
        if (m2316H.length != 2) {
            throw new C2205l0(C1499a.m632r("Unexpected URI format: ", uri));
        }
        String str = m2316H[1];
        if (m2316H[0].contains(";base64")) {
            try {
                this.f5923b = Base64.decode(str, 0);
            } catch (IllegalArgumentException e2) {
                throw new C2205l0(C1499a.m637w("Error while parsing Base64 encoded string: ", str), e2);
            }
        } else {
            this.f5923b = C2344d0.m2342t(URLDecoder.decode(str, "US-ASCII"));
        }
        long j2 = c2324p.f5939g;
        int length = j2 != -1 ? ((int) j2) + this.f5925d : this.f5923b.length;
        this.f5924c = length;
        if (length > this.f5923b.length || this.f5925d > length) {
            this.f5923b = null;
            throw new C2322n(0);
        }
        transferStarted(c2324p);
        return this.f5924c - this.f5925d;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        int i4 = this.f5924c - this.f5925d;
        if (i4 == 0) {
            return -1;
        }
        int min = Math.min(i3, i4);
        byte[] bArr2 = this.f5923b;
        int i5 = C2344d0.f6035a;
        System.arraycopy(bArr2, this.f5925d, bArr, i2, min);
        this.f5925d += min;
        bytesTransferred(min);
        return min;
    }
}
