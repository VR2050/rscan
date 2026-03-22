package p005b.p143g.p144a.p147m;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.collection.ArrayMap;
import androidx.collection.SimpleArrayMap;
import com.bumptech.glide.util.CachedHashCodeArrayMap;
import java.security.MessageDigest;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1581m;

/* renamed from: b.g.a.m.n */
/* loaded from: classes.dex */
public final class C1582n implements InterfaceC1579k {

    /* renamed from: b */
    public final ArrayMap<C1581m<?>, Object> f1995b = new CachedHashCodeArrayMap();

    @Nullable
    /* renamed from: a */
    public <T> T m827a(@NonNull C1581m<T> c1581m) {
        return this.f1995b.containsKey(c1581m) ? (T) this.f1995b.get(c1581m) : c1581m.f1991b;
    }

    /* renamed from: b */
    public void m828b(@NonNull C1582n c1582n) {
        this.f1995b.putAll((SimpleArrayMap<? extends C1581m<?>, ? extends Object>) c1582n.f1995b);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (obj instanceof C1582n) {
            return this.f1995b.equals(((C1582n) obj).f1995b);
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return this.f1995b.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Options{values=");
        m586H.append(this.f1995b);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        for (int i2 = 0; i2 < this.f1995b.size(); i2++) {
            C1581m<?> keyAt = this.f1995b.keyAt(i2);
            Object valueAt = this.f1995b.valueAt(i2);
            C1581m.b<?> bVar = keyAt.f1992c;
            if (keyAt.f1994e == null) {
                keyAt.f1994e = keyAt.f1993d.getBytes(InterfaceC1579k.f1988a);
            }
            bVar.mo826a(keyAt.f1994e, valueAt, messageDigest);
        }
    }
}
