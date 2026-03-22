package p005b.p199l.p200a.p201a.p208f1.p214f0;

import android.util.Pair;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2347g;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.o */
/* loaded from: classes.dex */
public final class C2024o implements InterfaceC2019j {

    /* renamed from: a */
    public final String f4034a;

    /* renamed from: b */
    public final C2360t f4035b;

    /* renamed from: c */
    public final C2359s f4036c;

    /* renamed from: d */
    public InterfaceC2052s f4037d;

    /* renamed from: e */
    public Format f4038e;

    /* renamed from: f */
    public String f4039f;

    /* renamed from: g */
    public int f4040g;

    /* renamed from: h */
    public int f4041h;

    /* renamed from: i */
    public int f4042i;

    /* renamed from: j */
    public int f4043j;

    /* renamed from: k */
    public long f4044k;

    /* renamed from: l */
    public boolean f4045l;

    /* renamed from: m */
    public int f4046m;

    /* renamed from: n */
    public int f4047n;

    /* renamed from: o */
    public int f4048o;

    /* renamed from: p */
    public boolean f4049p;

    /* renamed from: q */
    public long f4050q;

    /* renamed from: r */
    public int f4051r;

    /* renamed from: s */
    public long f4052s;

    /* renamed from: t */
    public int f4053t;

    public C2024o(@Nullable String str) {
        this.f4034a = str;
        C2360t c2360t = new C2360t(1024);
        this.f4035b = c2360t;
        this.f4036c = new C2359s(c2360t.f6133a);
    }

    /* renamed from: a */
    public static long m1599a(C2359s c2359s) {
        return c2359s.m2558f((c2359s.m2558f(2) + 1) * 8);
    }

    /* JADX WARN: Code restructure failed: missing block: B:135:0x0148, code lost:
    
        if (r23.f4045l == false) goto L85;
     */
    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1573b(p005b.p199l.p200a.p201a.p250p1.C2360t r24) {
        /*
            Method dump skipped, instructions count: 538
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2024o.mo1573b(b.l.a.a.p1.t):void");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: c */
    public void mo1574c() {
        this.f4040g = 0;
        this.f4045l = false;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: d */
    public void mo1575d() {
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: e */
    public void mo1576e(InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        dVar.m1584a();
        this.f4037d = interfaceC2042i.mo1625t(dVar.m1586c(), 1);
        this.f4039f = dVar.m1585b();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2019j
    /* renamed from: f */
    public void mo1577f(long j2, int i2) {
        this.f4044k = j2;
    }

    /* renamed from: g */
    public final int m1600g(C2359s c2359s) {
        int m2554b = c2359s.m2554b();
        Pair<Integer, Integer> m2358d = C2347g.m2358d(c2359s, true);
        this.f4051r = ((Integer) m2358d.first).intValue();
        this.f4053t = ((Integer) m2358d.second).intValue();
        return m2554b - c2359s.m2554b();
    }
}
