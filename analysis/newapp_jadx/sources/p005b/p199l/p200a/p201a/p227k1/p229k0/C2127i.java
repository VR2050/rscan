package p005b.p199l.p200a.p201a.p227k1.p229k0;

import com.google.android.exoplayer2.Format;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.k0.i */
/* loaded from: classes.dex */
public class C2127i extends AbstractC2119a {

    /* renamed from: n */
    public static final C2049p f4676n = new C2049p();

    /* renamed from: o */
    public final int f4677o;

    /* renamed from: p */
    public final long f4678p;

    /* renamed from: q */
    public final C2123e f4679q;

    /* renamed from: r */
    public long f4680r;

    /* renamed from: s */
    public volatile boolean f4681s;

    /* renamed from: t */
    public boolean f4682t;

    public C2127i(InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, int i2, Object obj, long j2, long j3, long j4, long j5, long j6, int i3, long j7, C2123e c2123e) {
        super(interfaceC2321m, c2324p, format, i2, obj, j2, j3, j4, j5, j6);
        this.f4677o = i3;
        this.f4678p = j7;
        this.f4679q = c2123e;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public final void mo1782a() {
        if (this.f4680r == 0) {
            C2121c c2121c = this.f4618l;
            c2121c.m1839a(this.f4678p);
            C2123e c2123e = this.f4679q;
            long j2 = this.f4616j;
            long j3 = j2 == -9223372036854775807L ? -9223372036854775807L : j2 - this.f4678p;
            long j4 = this.f4617k;
            c2123e.m1841b(c2121c, j3, j4 == -9223372036854775807L ? -9223372036854775807L : j4 - this.f4678p);
        }
        try {
            C2324p m2268c = this.f4623a.m2268c(this.f4680r);
            C2287d0 c2287d0 = this.f4630h;
            C2003e c2003e = new C2003e(c2287d0, m2268c.f5937e, c2287d0.open(m2268c));
            try {
                InterfaceC2041h interfaceC2041h = this.f4679q.f4631c;
                int i2 = 0;
                while (i2 == 0 && !this.f4681s) {
                    i2 = interfaceC2041h.mo1479d(c2003e, f4676n);
                }
                C4195m.m4771I(i2 != 1);
                if (r1 != null) {
                    try {
                        this.f4630h.f5796a.close();
                    } catch (IOException unused) {
                    }
                }
                this.f4682t = true;
            } finally {
                this.f4680r = c2003e.f3789d - this.f4623a.f5937e;
            }
        } finally {
            C2287d0 c2287d02 = this.f4630h;
            int i3 = C2344d0.f6035a;
            if (c2287d02 != null) {
                try {
                    c2287d02.f5796a.close();
                } catch (IOException unused2) {
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public final void mo1783b() {
        this.f4681s = true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l
    /* renamed from: c */
    public long mo1860c() {
        return this.f4690i + this.f4677o;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l
    /* renamed from: d */
    public boolean mo1861d() {
        return this.f4682t;
    }
}
