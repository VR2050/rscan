package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p170s.C1804f;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.t.y */
/* loaded from: classes.dex */
public final class C1657y implements InterfaceC1579k {

    /* renamed from: b */
    public static final C1804f<Class<?>, byte[]> f2328b = new C1804f<>(50);

    /* renamed from: c */
    public final InterfaceC1612b f2329c;

    /* renamed from: d */
    public final InterfaceC1579k f2330d;

    /* renamed from: e */
    public final InterfaceC1579k f2331e;

    /* renamed from: f */
    public final int f2332f;

    /* renamed from: g */
    public final int f2333g;

    /* renamed from: h */
    public final Class<?> f2334h;

    /* renamed from: i */
    public final C1582n f2335i;

    /* renamed from: j */
    public final InterfaceC1586r<?> f2336j;

    public C1657y(InterfaceC1612b interfaceC1612b, InterfaceC1579k interfaceC1579k, InterfaceC1579k interfaceC1579k2, int i2, int i3, InterfaceC1586r<?> interfaceC1586r, Class<?> cls, C1582n c1582n) {
        this.f2329c = interfaceC1612b;
        this.f2330d = interfaceC1579k;
        this.f2331e = interfaceC1579k2;
        this.f2332f = i2;
        this.f2333g = i3;
        this.f2336j = interfaceC1586r;
        this.f2334h = cls;
        this.f2335i = c1582n;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (!(obj instanceof C1657y)) {
            return false;
        }
        C1657y c1657y = (C1657y) obj;
        return this.f2333g == c1657y.f2333g && this.f2332f == c1657y.f2332f && C1807i.m1145b(this.f2336j, c1657y.f2336j) && this.f2334h.equals(c1657y.f2334h) && this.f2330d.equals(c1657y.f2330d) && this.f2331e.equals(c1657y.f2331e) && this.f2335i.equals(c1657y.f2335i);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        int hashCode = ((((this.f2331e.hashCode() + (this.f2330d.hashCode() * 31)) * 31) + this.f2332f) * 31) + this.f2333g;
        InterfaceC1586r<?> interfaceC1586r = this.f2336j;
        if (interfaceC1586r != null) {
            hashCode = (hashCode * 31) + interfaceC1586r.hashCode();
        }
        return this.f2335i.hashCode() + ((this.f2334h.hashCode() + (hashCode * 31)) * 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ResourceCacheKey{sourceKey=");
        m586H.append(this.f2330d);
        m586H.append(", signature=");
        m586H.append(this.f2331e);
        m586H.append(", width=");
        m586H.append(this.f2332f);
        m586H.append(", height=");
        m586H.append(this.f2333g);
        m586H.append(", decodedResourceClass=");
        m586H.append(this.f2334h);
        m586H.append(", transformation='");
        m586H.append(this.f2336j);
        m586H.append('\'');
        m586H.append(", options=");
        m586H.append(this.f2335i);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        byte[] bArr = (byte[]) this.f2329c.mo862c(8, byte[].class);
        ByteBuffer.wrap(bArr).putInt(this.f2332f).putInt(this.f2333g).array();
        this.f2331e.updateDiskCacheKey(messageDigest);
        this.f2330d.updateDiskCacheKey(messageDigest);
        messageDigest.update(bArr);
        InterfaceC1586r<?> interfaceC1586r = this.f2336j;
        if (interfaceC1586r != null) {
            interfaceC1586r.updateDiskCacheKey(messageDigest);
        }
        this.f2335i.updateDiskCacheKey(messageDigest);
        C1804f<Class<?>, byte[]> c1804f = f2328b;
        byte[] m1139a = c1804f.m1139a(this.f2334h);
        if (m1139a == null) {
            m1139a = this.f2334h.getName().getBytes(InterfaceC1579k.f1988a);
            c1804f.m1140d(this.f2334h, m1139a);
        }
        messageDigest.update(m1139a);
        this.f2329c.put(bArr);
    }
}
