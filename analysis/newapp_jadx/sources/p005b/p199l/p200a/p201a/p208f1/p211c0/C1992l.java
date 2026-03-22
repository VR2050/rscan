package p005b.p199l.p200a.p201a.p208f1.p211c0;

import com.alibaba.fastjson.asm.Label;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.c0.l */
/* loaded from: classes.dex */
public final class C1992l {

    /* renamed from: a */
    public final C1989i f3712a;

    /* renamed from: b */
    public final int f3713b;

    /* renamed from: c */
    public final long[] f3714c;

    /* renamed from: d */
    public final int[] f3715d;

    /* renamed from: e */
    public final int f3716e;

    /* renamed from: f */
    public final long[] f3717f;

    /* renamed from: g */
    public final int[] f3718g;

    /* renamed from: h */
    public final long f3719h;

    public C1992l(C1989i c1989i, long[] jArr, int[] iArr, int i2, long[] jArr2, int[] iArr2, long j2) {
        C4195m.m4765F(iArr.length == jArr2.length);
        C4195m.m4765F(jArr.length == jArr2.length);
        C4195m.m4765F(iArr2.length == jArr2.length);
        this.f3712a = c1989i;
        this.f3714c = jArr;
        this.f3715d = iArr;
        this.f3716e = i2;
        this.f3717f = jArr2;
        this.f3718g = iArr2;
        this.f3719h = j2;
        this.f3713b = jArr.length;
        if (iArr2.length > 0) {
            int length = iArr2.length - 1;
            iArr2[length] = iArr2[length] | Label.FORWARD_REFERENCE_TYPE_WIDE;
        }
    }

    /* renamed from: a */
    public int m1542a(long j2) {
        for (int m2326d = C2344d0.m2326d(this.f3717f, j2, true, false); m2326d >= 0; m2326d--) {
            if ((this.f3718g[m2326d] & 1) != 0) {
                return m2326d;
            }
        }
        return -1;
    }

    /* renamed from: b */
    public int m1543b(long j2) {
        for (int m2324b = C2344d0.m2324b(this.f3717f, j2, true, false); m2324b < this.f3717f.length; m2324b++) {
            if ((this.f3718g[m2324b] & 1) != 0) {
                return m2324b;
            }
        }
        return -1;
    }
}
