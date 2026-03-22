package p005b.p199l.p200a.p201a.p208f1.p213e0;

import com.google.android.exoplayer2.Format;
import java.io.IOException;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.e0.a */
/* loaded from: classes.dex */
public final class C2004a implements InterfaceC2041h {

    /* renamed from: a */
    public final Format f3793a;

    /* renamed from: c */
    public InterfaceC2052s f3795c;

    /* renamed from: e */
    public int f3797e;

    /* renamed from: f */
    public long f3798f;

    /* renamed from: g */
    public int f3799g;

    /* renamed from: h */
    public int f3800h;

    /* renamed from: b */
    public final C2360t f3794b = new C2360t(9);

    /* renamed from: d */
    public int f3796d = 0;

    public C2004a(Format format) {
        this.f3793a = format;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        while (true) {
            int i2 = this.f3796d;
            boolean z = false;
            boolean z2 = true;
            if (i2 == 0) {
                this.f3794b.m2592x();
                if (c2003e.m1568h(this.f3794b.f6133a, 0, 8, true)) {
                    if (this.f3794b.m2573e() != 1380139777) {
                        throw new IOException("Input not RawCC");
                    }
                    this.f3797e = this.f3794b.m2585q();
                    z = true;
                }
                if (!z) {
                    return -1;
                }
                this.f3796d = 1;
            } else {
                if (i2 != 1) {
                    if (i2 != 2) {
                        throw new IllegalStateException();
                    }
                    while (this.f3799g > 0) {
                        this.f3794b.m2592x();
                        c2003e.m1568h(this.f3794b.f6133a, 0, 3, false);
                        this.f3795c.mo1613b(this.f3794b, 3);
                        this.f3800h += 3;
                        this.f3799g--;
                    }
                    int i3 = this.f3800h;
                    if (i3 > 0) {
                        this.f3795c.mo1614c(this.f3798f, 1, i3, 0, null);
                    }
                    this.f3796d = 1;
                    return 0;
                }
                this.f3794b.m2592x();
                int i4 = this.f3797e;
                if (i4 == 0) {
                    if (c2003e.m1568h(this.f3794b.f6133a, 0, 5, true)) {
                        this.f3798f = (this.f3794b.m2586r() * 1000) / 45;
                        this.f3799g = this.f3794b.m2585q();
                        this.f3800h = 0;
                    }
                    z2 = false;
                } else {
                    if (i4 != 1) {
                        StringBuilder m586H = C1499a.m586H("Unsupported version number: ");
                        m586H.append(this.f3797e);
                        throw new C2205l0(m586H.toString());
                    }
                    if (c2003e.m1568h(this.f3794b.f6133a, 0, 9, true)) {
                        this.f3798f = this.f3794b.m2579k();
                        this.f3799g = this.f3794b.m2585q();
                        this.f3800h = 0;
                    }
                    z2 = false;
                }
                if (!z2) {
                    this.f3796d = 0;
                    return -1;
                }
                this.f3796d = 2;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        interfaceC2042i.mo1623a(new InterfaceC2050q.b(-9223372036854775807L, 0L));
        this.f3795c = interfaceC2042i.mo1625t(0, 3);
        interfaceC2042i.mo1624o();
        this.f3795c.mo1615d(this.f3793a);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3796d = 0;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        this.f3794b.m2592x();
        c2003e.m1565e(this.f3794b.f6133a, 0, 8, false);
        return this.f3794b.m2573e() == 1380139777;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
