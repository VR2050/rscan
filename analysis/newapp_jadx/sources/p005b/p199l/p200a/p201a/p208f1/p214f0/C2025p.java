package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.C2048o;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.p */
/* loaded from: classes.dex */
public final class C2025p implements InterfaceC2019j {

    /* renamed from: a */
    public final C2360t f4054a;

    /* renamed from: b */
    public final C2048o f4055b;

    /* renamed from: c */
    public final String f4056c;

    /* renamed from: d */
    public String f4057d;

    /* renamed from: e */
    public InterfaceC2052s f4058e;

    /* renamed from: f */
    public int f4059f = 0;

    /* renamed from: g */
    public int f4060g;

    /* renamed from: h */
    public boolean f4061h;

    /* renamed from: i */
    public boolean f4062i;

    /* renamed from: j */
    public long f4063j;

    /* renamed from: k */
    public int f4064k;

    /* renamed from: l */
    public long f4065l;

    public C2025p(String str) {
        C2360t c2360t = new C2360t(4);
        this.f4054a = c2360t;
        c2360t.f6133a[0] = -1;
        this.f4055b = new C2048o();
        this.f4056c = str;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    public void mo1573b(C2360t c2360t) {
        while (c2360t.m2569a() > 0) {
            int i2 = this.f4059f;
            if (i2 == 0) {
                byte[] bArr = c2360t.f6133a;
                int i3 = c2360t.f6134b;
                int i4 = c2360t.f6135c;
                while (true) {
                    if (i3 >= i4) {
                        c2360t.m2567C(i4);
                        break;
                    }
                    boolean z = (bArr[i3] & 255) == 255;
                    boolean z2 = this.f4062i && (bArr[i3] & 224) == 224;
                    this.f4062i = z;
                    if (z2) {
                        c2360t.m2567C(i3 + 1);
                        this.f4062i = false;
                        this.f4054a.f6133a[1] = bArr[i3];
                        this.f4060g = 2;
                        this.f4059f = 1;
                        break;
                    }
                    i3++;
                }
            } else if (i2 == 1) {
                int min = Math.min(c2360t.m2569a(), 4 - this.f4060g);
                c2360t.m2572d(this.f4054a.f6133a, this.f4060g, min);
                int i5 = this.f4060g + min;
                this.f4060g = i5;
                if (i5 >= 4) {
                    this.f4054a.m2567C(0);
                    if (C2048o.m1636d(this.f4054a.m2573e(), this.f4055b)) {
                        C2048o c2048o = this.f4055b;
                        this.f4064k = c2048o.f4182j;
                        if (!this.f4061h) {
                            int i6 = c2048o.f4183k;
                            this.f4063j = (c2048o.f4186n * 1000000) / i6;
                            this.f4058e.mo1615d(Format.m4024A(this.f4057d, c2048o.f4181i, null, -1, 4096, c2048o.f4184l, i6, null, null, 0, this.f4056c));
                            this.f4061h = true;
                        }
                        this.f4054a.m2567C(0);
                        this.f4058e.mo1613b(this.f4054a, 4);
                        this.f4059f = 2;
                    } else {
                        this.f4060g = 0;
                        this.f4059f = 1;
                    }
                }
            } else {
                if (i2 != 2) {
                    throw new IllegalStateException();
                }
                int min2 = Math.min(c2360t.m2569a(), this.f4064k - this.f4060g);
                this.f4058e.mo1613b(c2360t, min2);
                int i7 = this.f4060g + min2;
                this.f4060g = i7;
                int i8 = this.f4064k;
                if (i7 >= i8) {
                    this.f4058e.mo1614c(this.f4065l, 1, i8, 0, null);
                    this.f4065l += this.f4063j;
                    this.f4060g = 0;
                    this.f4059f = 0;
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        this.f4059f = 0;
        this.f4060g = 0;
        this.f4062i = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        this.f4057d = dVar.m1585b();
        this.f4058e = interfaceC2042i.mo1625t(dVar.m1586c(), 1);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        this.f4065l = j2;
    }
}
