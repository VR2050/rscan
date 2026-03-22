package p005b.p143g.p144a.p169r;

import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.r.a */
/* loaded from: classes.dex */
public final class C1795a implements InterfaceC1579k {

    /* renamed from: b */
    public static final /* synthetic */ int f2738b = 0;

    /* renamed from: c */
    public final int f2739c;

    /* renamed from: d */
    public final InterfaceC1579k f2740d;

    public C1795a(int i2, InterfaceC1579k interfaceC1579k) {
        this.f2739c = i2;
        this.f2740d = interfaceC1579k;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (!(obj instanceof C1795a)) {
            return false;
        }
        C1795a c1795a = (C1795a) obj;
        return this.f2739c == c1795a.f2739c && this.f2740d.equals(c1795a.f2740d);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return C1807i.m1149f(this.f2740d, this.f2739c);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        this.f2740d.updateDiskCacheKey(messageDigest);
        messageDigest.update(ByteBuffer.allocate(4).putInt(this.f2739c).array());
    }
}
