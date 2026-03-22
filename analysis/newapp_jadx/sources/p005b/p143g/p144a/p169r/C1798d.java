package p005b.p143g.p144a.p169r;

import androidx.annotation.NonNull;
import java.security.MessageDigest;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;

/* renamed from: b.g.a.r.d */
/* loaded from: classes.dex */
public final class C1798d implements InterfaceC1579k {

    /* renamed from: b */
    public final Object f2743b;

    public C1798d(@NonNull Object obj) {
        Objects.requireNonNull(obj, "Argument must not be null");
        this.f2743b = obj;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (obj instanceof C1798d) {
            return this.f2743b.equals(((C1798d) obj).f2743b);
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f2743b.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ObjectKey{object=");
        m586H.append(this.f2743b);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        messageDigest.update(this.f2743b.toString().getBytes(InterfaceC1579k.f1988a));
    }
}
