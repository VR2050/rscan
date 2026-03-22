package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.alibaba.fastjson.asm.Opcodes;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.k */
/* loaded from: classes.dex */
public final class C2020k implements InterfaceC2019j {

    /* renamed from: a */
    public static final double[] f3930a = {23.976023976023978d, 24.0d, 25.0d, 29.97002997002997d, 30.0d, 50.0d, 59.94005994005994d, 60.0d};

    /* renamed from: b */
    public String f3931b;

    /* renamed from: c */
    public InterfaceC2052s f3932c;

    /* renamed from: d */
    public boolean f3933d;

    /* renamed from: e */
    public long f3934e;

    /* renamed from: f */
    public final C2013d0 f3935f;

    /* renamed from: g */
    public final C2360t f3936g;

    /* renamed from: h */
    public final boolean[] f3937h = new boolean[4];

    /* renamed from: i */
    public final a f3938i = new a(128);

    /* renamed from: j */
    public final C2026q f3939j;

    /* renamed from: k */
    public long f3940k;

    /* renamed from: l */
    public boolean f3941l;

    /* renamed from: m */
    public long f3942m;

    /* renamed from: n */
    public long f3943n;

    /* renamed from: o */
    public long f3944o;

    /* renamed from: p */
    public boolean f3945p;

    /* renamed from: q */
    public boolean f3946q;

    /* renamed from: b.l.a.a.f1.f0.k$a */
    public static final class a {

        /* renamed from: a */
        public static final byte[] f3947a = {0, 0, 1};

        /* renamed from: b */
        public boolean f3948b;

        /* renamed from: c */
        public int f3949c;

        /* renamed from: d */
        public int f3950d;

        /* renamed from: e */
        public byte[] f3951e;

        public a(int i2) {
            this.f3951e = new byte[i2];
        }

        /* renamed from: a */
        public void m1595a(byte[] bArr, int i2, int i3) {
            if (this.f3948b) {
                int i4 = i3 - i2;
                byte[] bArr2 = this.f3951e;
                int length = bArr2.length;
                int i5 = this.f3949c;
                if (length < i5 + i4) {
                    this.f3951e = Arrays.copyOf(bArr2, (i5 + i4) * 2);
                }
                System.arraycopy(bArr, i2, this.f3951e, this.f3949c, i4);
                this.f3949c += i4;
            }
        }
    }

    public C2020k(C2013d0 c2013d0) {
        this.f3935f = c2013d0;
        if (c2013d0 != null) {
            this.f3939j = new C2026q(Opcodes.GETSTATIC, 128);
            this.f3936g = new C2360t();
        } else {
            this.f3939j = null;
            this.f3936g = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00ed  */
    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1573b(p005b.p199l.p200a.p201a.p250p1.C2360t r30) {
        /*
            Method dump skipped, instructions count: 526
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2020k.mo1573b(b.l.a.a.p1.t):void");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        C2358r.m2548a(this.f3937h);
        a aVar = this.f3938i;
        aVar.f3948b = false;
        aVar.f3949c = 0;
        aVar.f3950d = 0;
        if (this.f3935f != null) {
            this.f3939j.m1603c();
        }
        this.f3940k = 0L;
        this.f3941l = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        this.f3931b = dVar.m1585b();
        this.f3932c = interfaceC2042i.mo1625t(dVar.m1586c(), 2);
        C2013d0 c2013d0 = this.f3935f;
        if (c2013d0 != null) {
            for (int i2 = 0; i2 < c2013d0.f3878b.length; i2++) {
                dVar.m1584a();
                InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 3);
                Format format = c2013d0.f3877a.get(i2);
                String str = format.f9245l;
                C4195m.m4761D("application/cea-608".equals(str) || "application/cea-708".equals(str), "Invalid closed caption mime type provided: " + str);
                mo1625t.mo1615d(Format.m4032I(dVar.m1585b(), str, null, -1, format.f9239f, format.f9233D, format.f9234E, null, Long.MAX_VALUE, format.f9247n));
                c2013d0.f3878b[i2] = mo1625t;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        this.f3942m = j2;
    }
}
