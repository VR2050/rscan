package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;

/* renamed from: b.g.a.m.t.o */
/* loaded from: classes.dex */
public class C1647o implements InterfaceC1579k {

    /* renamed from: b */
    public final Object f2284b;

    /* renamed from: c */
    public final int f2285c;

    /* renamed from: d */
    public final int f2286d;

    /* renamed from: e */
    public final Class<?> f2287e;

    /* renamed from: f */
    public final Class<?> f2288f;

    /* renamed from: g */
    public final InterfaceC1579k f2289g;

    /* renamed from: h */
    public final Map<Class<?>, InterfaceC1586r<?>> f2290h;

    /* renamed from: i */
    public final C1582n f2291i;

    /* renamed from: j */
    public int f2292j;

    public C1647o(Object obj, InterfaceC1579k interfaceC1579k, int i2, int i3, Map<Class<?>, InterfaceC1586r<?>> map, Class<?> cls, Class<?> cls2, C1582n c1582n) {
        Objects.requireNonNull(obj, "Argument must not be null");
        this.f2284b = obj;
        Objects.requireNonNull(interfaceC1579k, "Signature must not be null");
        this.f2289g = interfaceC1579k;
        this.f2285c = i2;
        this.f2286d = i3;
        Objects.requireNonNull(map, "Argument must not be null");
        this.f2290h = map;
        Objects.requireNonNull(cls, "Resource class must not be null");
        this.f2287e = cls;
        Objects.requireNonNull(cls2, "Transcode class must not be null");
        this.f2288f = cls2;
        Objects.requireNonNull(c1582n, "Argument must not be null");
        this.f2291i = c1582n;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (!(obj instanceof C1647o)) {
            return false;
        }
        C1647o c1647o = (C1647o) obj;
        return this.f2284b.equals(c1647o.f2284b) && this.f2289g.equals(c1647o.f2289g) && this.f2286d == c1647o.f2286d && this.f2285c == c1647o.f2285c && this.f2290h.equals(c1647o.f2290h) && this.f2287e.equals(c1647o.f2287e) && this.f2288f.equals(c1647o.f2288f) && this.f2291i.equals(c1647o.f2291i);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        if (this.f2292j == 0) {
            int hashCode = this.f2284b.hashCode();
            this.f2292j = hashCode;
            int hashCode2 = this.f2289g.hashCode() + (hashCode * 31);
            this.f2292j = hashCode2;
            int i2 = (hashCode2 * 31) + this.f2285c;
            this.f2292j = i2;
            int i3 = (i2 * 31) + this.f2286d;
            this.f2292j = i3;
            int hashCode3 = this.f2290h.hashCode() + (i3 * 31);
            this.f2292j = hashCode3;
            int hashCode4 = this.f2287e.hashCode() + (hashCode3 * 31);
            this.f2292j = hashCode4;
            int hashCode5 = this.f2288f.hashCode() + (hashCode4 * 31);
            this.f2292j = hashCode5;
            this.f2292j = this.f2291i.hashCode() + (hashCode5 * 31);
        }
        return this.f2292j;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("EngineKey{model=");
        m586H.append(this.f2284b);
        m586H.append(", width=");
        m586H.append(this.f2285c);
        m586H.append(", height=");
        m586H.append(this.f2286d);
        m586H.append(", resourceClass=");
        m586H.append(this.f2287e);
        m586H.append(", transcodeClass=");
        m586H.append(this.f2288f);
        m586H.append(", signature=");
        m586H.append(this.f2289g);
        m586H.append(", hashCode=");
        m586H.append(this.f2292j);
        m586H.append(", transformations=");
        m586H.append(this.f2290h);
        m586H.append(", options=");
        m586H.append(this.f2291i);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        throw new UnsupportedOperationException();
    }
}
