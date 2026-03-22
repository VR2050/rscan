package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.Nullable;
import java.util.TreeSet;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.o1.h0.m */
/* loaded from: classes.dex */
public final class C2307m {

    /* renamed from: a */
    public final int f5870a;

    /* renamed from: b */
    public final String f5871b;

    /* renamed from: c */
    public final TreeSet<C2316v> f5872c = new TreeSet<>();

    /* renamed from: d */
    public C2312r f5873d;

    /* renamed from: e */
    public boolean f5874e;

    public C2307m(int i2, String str, C2312r c2312r) {
        this.f5870a = i2;
        this.f5871b = str;
        this.f5873d = c2312r;
    }

    /* renamed from: a */
    public long m2227a(long j2, long j3) {
        C2316v m2228b = m2228b(j2);
        if (!m2228b.f5866g) {
            long j4 = m2228b.f5865f;
            if (j4 == -1) {
                j4 = Long.MAX_VALUE;
            }
            return -Math.min(j4, j3);
        }
        long j5 = j2 + j3;
        long j6 = m2228b.f5864e + m2228b.f5865f;
        if (j6 < j5) {
            for (C2316v c2316v : this.f5872c.tailSet(m2228b, false)) {
                long j7 = c2316v.f5864e;
                if (j7 > j6) {
                    break;
                }
                j6 = Math.max(j6, j7 + c2316v.f5865f);
                if (j6 >= j5) {
                    break;
                }
            }
        }
        return Math.min(j6 - j2, j3);
    }

    /* renamed from: b */
    public C2316v m2228b(long j2) {
        C2316v c2316v = new C2316v(this.f5871b, j2, -1L, -9223372036854775807L, null);
        C2316v floor = this.f5872c.floor(c2316v);
        if (floor != null && floor.f5864e + floor.f5865f > j2) {
            return floor;
        }
        C2316v ceiling = this.f5872c.ceiling(c2316v);
        String str = this.f5871b;
        return ceiling == null ? new C2316v(str, j2, -1L, -9223372036854775807L, null) : new C2316v(str, j2, ceiling.f5864e - j2, -9223372036854775807L, null);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2307m.class != obj.getClass()) {
            return false;
        }
        C2307m c2307m = (C2307m) obj;
        return this.f5870a == c2307m.f5870a && this.f5871b.equals(c2307m.f5871b) && this.f5872c.equals(c2307m.f5872c) && this.f5873d.equals(c2307m.f5873d);
    }

    public int hashCode() {
        return this.f5873d.hashCode() + C1499a.m598T(this.f5871b, this.f5870a * 31, 31);
    }
}
