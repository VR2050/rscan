package p005b.p199l.p200a.p201a.p227k1.p229k0;

import com.google.android.exoplayer2.Format;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.k0.n */
/* loaded from: classes.dex */
public final class C2132n extends AbstractC2119a {

    /* renamed from: n */
    public final int f4692n;

    /* renamed from: o */
    public final Format f4693o;

    /* renamed from: p */
    public long f4694p;

    /* renamed from: q */
    public boolean f4695q;

    public C2132n(InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, int i2, Object obj, long j2, long j3, long j4, int i3, Format format2) {
        super(interfaceC2321m, c2324p, format, i2, obj, j2, j3, -9223372036854775807L, -9223372036854775807L, j4);
        this.f4692n = i3;
        this.f4693o = format2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public void mo1782a() {
        C2121c c2121c = this.f4618l;
        c2121c.m1839a(0L);
        InterfaceC2052s m1840b = c2121c.m1840b(0, this.f4692n);
        m1840b.mo1615d(this.f4693o);
        try {
            long open = this.f4630h.open(this.f4623a.m2268c(this.f4694p));
            if (open != -1) {
                open += this.f4694p;
            }
            C2003e c2003e = new C2003e(this.f4630h, this.f4694p, open);
            for (int i2 = 0; i2 != -1; i2 = m1840b.mo1612a(c2003e, Integer.MAX_VALUE, true)) {
                this.f4694p += i2;
            }
            m1840b.mo1614c(this.f4628f, 1, (int) this.f4694p, 0, null);
            if (r0 != null) {
                try {
                    this.f4630h.f5796a.close();
                } catch (IOException unused) {
                }
            }
            this.f4695q = true;
        } finally {
            C2287d0 c2287d0 = this.f4630h;
            int i3 = C2344d0.f6035a;
            if (c2287d0 != null) {
                try {
                    c2287d0.f5796a.close();
                } catch (IOException unused2) {
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public void mo1783b() {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l
    /* renamed from: d */
    public boolean mo1861d() {
        return this.f4695q;
    }
}
