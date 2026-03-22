package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.security.MessageDigest;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;

/* renamed from: b.g.a.m.t.e */
/* loaded from: classes.dex */
public final class C1636e implements InterfaceC1579k {

    /* renamed from: b */
    public final InterfaceC1579k f2135b;

    /* renamed from: c */
    public final InterfaceC1579k f2136c;

    public C1636e(InterfaceC1579k interfaceC1579k, InterfaceC1579k interfaceC1579k2) {
        this.f2135b = interfaceC1579k;
        this.f2136c = interfaceC1579k2;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (!(obj instanceof C1636e)) {
            return false;
        }
        C1636e c1636e = (C1636e) obj;
        return this.f2135b.equals(c1636e.f2135b) && this.f2136c.equals(c1636e.f2136c);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f2136c.hashCode() + (this.f2135b.hashCode() * 31);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("DataCacheKey{sourceKey=");
        m586H.append(this.f2135b);
        m586H.append(", signature=");
        m586H.append(this.f2136c);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        this.f2135b.updateDiskCacheKey(messageDigest);
        this.f2136c.updateDiskCacheKey(messageDigest);
    }
}
