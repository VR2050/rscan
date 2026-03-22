package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.f1.r */
/* loaded from: classes.dex */
public final class C2051r {

    /* renamed from: a */
    public static final C2051r f4192a = new C2051r(0, 0);

    /* renamed from: b */
    public final long f4193b;

    /* renamed from: c */
    public final long f4194c;

    public C2051r(long j2, long j3) {
        this.f4193b = j2;
        this.f4194c = j3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2051r.class != obj.getClass()) {
            return false;
        }
        C2051r c2051r = (C2051r) obj;
        return this.f4193b == c2051r.f4193b && this.f4194c == c2051r.f4194c;
    }

    public int hashCode() {
        return (((int) this.f4193b) * 31) + ((int) this.f4194c);
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("[timeUs=");
        m586H.append(this.f4193b);
        m586H.append(", position=");
        m586H.append(this.f4194c);
        m586H.append("]");
        return m586H.toString();
    }
}
