package p005b.p143g.p144a.p170s;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.s.h */
/* loaded from: classes.dex */
public class C1806h {

    /* renamed from: a */
    public Class<?> f2764a;

    /* renamed from: b */
    public Class<?> f2765b;

    /* renamed from: c */
    public Class<?> f2766c;

    public C1806h() {
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1806h.class != obj.getClass()) {
            return false;
        }
        C1806h c1806h = (C1806h) obj;
        return this.f2764a.equals(c1806h.f2764a) && this.f2765b.equals(c1806h.f2765b) && C1807i.m1145b(this.f2766c, c1806h.f2766c);
    }

    public int hashCode() {
        int hashCode = (this.f2765b.hashCode() + (this.f2764a.hashCode() * 31)) * 31;
        Class<?> cls = this.f2766c;
        return hashCode + (cls != null ? cls.hashCode() : 0);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("MultiClassKey{first=");
        m586H.append(this.f2764a);
        m586H.append(", second=");
        m586H.append(this.f2765b);
        m586H.append('}');
        return m586H.toString();
    }

    public C1806h(@NonNull Class<?> cls, @NonNull Class<?> cls2, @Nullable Class<?> cls3) {
        this.f2764a = cls;
        this.f2765b = cls2;
        this.f2766c = cls3;
    }
}
