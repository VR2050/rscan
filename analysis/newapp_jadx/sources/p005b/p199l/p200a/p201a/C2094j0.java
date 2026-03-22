package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.j0 */
/* loaded from: classes.dex */
public final class C2094j0 {

    /* renamed from: a */
    public final InterfaceC2202y.a f4415a;

    /* renamed from: b */
    public final long f4416b;

    /* renamed from: c */
    public final long f4417c;

    /* renamed from: d */
    public final long f4418d;

    /* renamed from: e */
    public final long f4419e;

    /* renamed from: f */
    public final boolean f4420f;

    /* renamed from: g */
    public final boolean f4421g;

    public C2094j0(InterfaceC2202y.a aVar, long j2, long j3, long j4, long j5, boolean z, boolean z2) {
        this.f4415a = aVar;
        this.f4416b = j2;
        this.f4417c = j3;
        this.f4418d = j4;
        this.f4419e = j5;
        this.f4420f = z;
        this.f4421g = z2;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2094j0.class != obj.getClass()) {
            return false;
        }
        C2094j0 c2094j0 = (C2094j0) obj;
        return this.f4416b == c2094j0.f4416b && this.f4417c == c2094j0.f4417c && this.f4418d == c2094j0.f4418d && this.f4419e == c2094j0.f4419e && this.f4420f == c2094j0.f4420f && this.f4421g == c2094j0.f4421g && C2344d0.m2323a(this.f4415a, c2094j0.f4415a);
    }

    public int hashCode() {
        return ((((((((((((this.f4415a.hashCode() + 527) * 31) + ((int) this.f4416b)) * 31) + ((int) this.f4417c)) * 31) + ((int) this.f4418d)) * 31) + ((int) this.f4419e)) * 31) + (this.f4420f ? 1 : 0)) * 31) + (this.f4421g ? 1 : 0);
    }
}
