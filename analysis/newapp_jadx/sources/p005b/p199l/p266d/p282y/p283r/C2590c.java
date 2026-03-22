package p005b.p199l.p266d.p282y.p283r;

import p005b.p199l.p266d.C2536r;

/* renamed from: b.l.d.y.r.c */
/* loaded from: classes2.dex */
public final class C2590c {

    /* renamed from: a */
    public final int f7074a;

    /* renamed from: b */
    public final int[] f7075b;

    /* renamed from: c */
    public final C2536r[] f7076c;

    public C2590c(int i2, int[] iArr, int i3, int i4, int i5) {
        this.f7074a = i2;
        this.f7075b = iArr;
        float f2 = i5;
        this.f7076c = new C2536r[]{new C2536r(i3, f2), new C2536r(i4, f2)};
    }

    public boolean equals(Object obj) {
        return (obj instanceof C2590c) && this.f7074a == ((C2590c) obj).f7074a;
    }

    public int hashCode() {
        return this.f7074a;
    }
}
