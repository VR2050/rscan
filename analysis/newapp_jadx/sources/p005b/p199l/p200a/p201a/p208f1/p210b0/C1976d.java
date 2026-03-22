package p005b.p199l.p200a.p201a.p208f1.p210b0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.metadata.Metadata;
import java.io.EOFException;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2046m;
import p005b.p199l.p200a.p201a.p208f1.C2047n;
import p005b.p199l.p200a.p201a.p208f1.C2048o;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.b0.d */
/* loaded from: classes.dex */
public final class C1976d implements InterfaceC2041h {

    /* renamed from: a */
    public static final /* synthetic */ int f3551a = 0;

    /* renamed from: b */
    public final int f3552b;

    /* renamed from: c */
    public final long f3553c;

    /* renamed from: d */
    public final C2360t f3554d;

    /* renamed from: e */
    public final C2048o f3555e;

    /* renamed from: f */
    public final C2046m f3556f;

    /* renamed from: g */
    public final C2047n f3557g;

    /* renamed from: h */
    public InterfaceC2042i f3558h;

    /* renamed from: i */
    public InterfaceC2052s f3559i;

    /* renamed from: j */
    public int f3560j;

    /* renamed from: k */
    public Metadata f3561k;

    /* renamed from: l */
    @Nullable
    public InterfaceC1977e f3562l;

    /* renamed from: m */
    public boolean f3563m;

    /* renamed from: n */
    public long f3564n;

    /* renamed from: o */
    public long f3565o;

    /* renamed from: p */
    public long f3566p;

    /* renamed from: q */
    public int f3567q;

    public C1976d() {
        this(0, -9223372036854775807L);
    }

    /* renamed from: b */
    public static boolean m1505b(int i2, long j2) {
        return ((long) (i2 & (-128000))) == (j2 & (-128000));
    }

    /* renamed from: a */
    public final InterfaceC1977e m1506a(C2003e c2003e) {
        c2003e.m1565e(this.f3554d.f6133a, 0, 4, false);
        this.f3554d.m2567C(0);
        C2048o.m1636d(this.f3554d.m2573e(), this.f3555e);
        return new C1974b(c2003e.f3788c, c2003e.f3789d, this.f3555e);
    }

    /* renamed from: c */
    public final boolean m1507c(C2003e c2003e) {
        InterfaceC1977e interfaceC1977e = this.f3562l;
        if (interfaceC1977e != null) {
            long mo1503b = interfaceC1977e.mo1503b();
            if (mo1503b != -1 && c2003e.m1564d() > mo1503b - 4) {
                return true;
            }
        }
        try {
            return !c2003e.m1565e(this.f3554d.f6133a, 0, 4, true);
        } catch (EOFException unused) {
            return true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0058, code lost:
    
        if (r8 != 1231971951) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:108:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x01d5  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0072 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x01e7  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x028b  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x028e  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x023d  */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r38, p005b.p199l.p200a.p201a.p208f1.C2049p r39) {
        /*
            Method dump skipped, instructions count: 868
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3558h = interfaceC2042i;
        this.f3559i = interfaceC2042i.mo1625t(0, 1);
        this.f3558h.mo1624o();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f3560j = 0;
        this.f3564n = -9223372036854775807L;
        this.f3565o = 0L;
        this.f3567q = 0;
    }

    /* JADX WARN: Code restructure failed: missing block: B:50:0x0099, code lost:
    
        if (r12 == false) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x009b, code lost:
    
        r11.m1569i(r3 + r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00a2, code lost:
    
        r10.f3560j = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00a4, code lost:
    
        return true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00a0, code lost:
    
        r11.f3791f = 0;
     */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m1508g(p005b.p199l.p200a.p201a.p208f1.C2003e r11, boolean r12) {
        /*
            r10 = this;
            if (r12 == 0) goto L5
            r0 = 16384(0x4000, float:2.2959E-41)
            goto L7
        L5:
            r0 = 131072(0x20000, float:1.83671E-40)
        L7:
            r1 = 0
            r11.f3791f = r1
            long r2 = r11.f3789d
            r4 = 0
            r6 = 1
            int r7 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r7 != 0) goto L3d
            int r2 = r10.f3552b
            r2 = r2 & 2
            if (r2 != 0) goto L1b
            r2 = 1
            goto L1c
        L1b:
            r2 = 0
        L1c:
            if (r2 == 0) goto L20
            r2 = 0
            goto L22
        L20:
            b.l.a.a.f1.b0.a r2 = new p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.a() { // from class: b.l.a.a.f1.b0.a
                static {
                    /*
                        b.l.a.a.f1.b0.a r0 = new b.l.a.a.f1.b0.a
                        r0.<init>()
                        
                        // error: 0x0005: SPUT (r0 I:b.l.a.a.f1.b0.a) b.l.a.a.f1.b0.a.a b.l.a.a.f1.b0.a
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p210b0.C1973a.<clinit>():void");
                }

                {
                    /*
                        r0 = this;
                        r0.<init>()
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p210b0.C1973a.<init>():void");
                }

                @Override // p005b.p199l.p200a.p201a.p220h1.p223i.C2088b.a
                /* renamed from: a */
                public final boolean mo1501a(int r4, int r5, int r6, int r7, int r8) {
                    /*
                        r3 = this;
                        int r0 = p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d.f3551a
                        r0 = 2
                        r1 = 77
                        r2 = 67
                        if (r5 != r2) goto L13
                        r2 = 79
                        if (r6 != r2) goto L13
                        if (r7 != r1) goto L13
                        if (r8 == r1) goto L21
                        if (r4 == r0) goto L21
                    L13:
                        if (r5 != r1) goto L23
                        r5 = 76
                        if (r6 != r5) goto L23
                        if (r7 != r5) goto L23
                        r5 = 84
                        if (r8 == r5) goto L21
                        if (r4 != r0) goto L23
                    L21:
                        r4 = 1
                        goto L24
                    L23:
                        r4 = 0
                    L24:
                        return r4
                    */
                    throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p210b0.C1973a.mo1501a(int, int, int, int, int):boolean");
                }
            }
        L22:
            b.l.a.a.f1.n r3 = r10.f3557g
            com.google.android.exoplayer2.metadata.Metadata r2 = r3.m1632a(r11, r2)
            r10.f3561k = r2
            if (r2 == 0) goto L31
            b.l.a.a.f1.m r3 = r10.f3556f
            r3.m1631b(r2)
        L31:
            long r2 = r11.m1564d()
            int r3 = (int) r2
            if (r12 != 0) goto L3b
            r11.m1569i(r3)
        L3b:
            r2 = 0
            goto L3f
        L3d:
            r2 = 0
            r3 = 0
        L3f:
            r4 = 0
            r5 = 0
        L41:
            boolean r7 = r10.m1507c(r11)
            if (r7 == 0) goto L50
            if (r4 <= 0) goto L4a
            goto L99
        L4a:
            java.io.EOFException r11 = new java.io.EOFException
            r11.<init>()
            throw r11
        L50:
            b.l.a.a.p1.t r7 = r10.f3554d
            r7.m2567C(r1)
            b.l.a.a.p1.t r7 = r10.f3554d
            int r7 = r7.m2573e()
            if (r2 == 0) goto L64
            long r8 = (long) r2
            boolean r8 = m1505b(r7, r8)
            if (r8 == 0) goto L6b
        L64:
            int r8 = p005b.p199l.p200a.p201a.p208f1.C2048o.m1633a(r7)
            r9 = -1
            if (r8 != r9) goto L8b
        L6b:
            int r2 = r5 + 1
            if (r5 != r0) goto L7a
            if (r12 == 0) goto L72
            return r1
        L72:
            b.l.a.a.l0 r11 = new b.l.a.a.l0
            java.lang.String r12 = "Searched too many bytes."
            r11.<init>(r12)
            throw r11
        L7a:
            if (r12 == 0) goto L84
            r11.f3791f = r1
            int r4 = r3 + r2
            r11.m1561a(r4, r1)
            goto L87
        L84:
            r11.m1569i(r6)
        L87:
            r5 = r2
            r2 = 0
            r4 = 0
            goto L41
        L8b:
            int r4 = r4 + 1
            if (r4 != r6) goto L96
            b.l.a.a.f1.o r2 = r10.f3555e
            p005b.p199l.p200a.p201a.p208f1.C2048o.m1636d(r7, r2)
            r2 = r7
            goto La5
        L96:
            r7 = 4
            if (r4 != r7) goto La5
        L99:
            if (r12 == 0) goto La0
            int r3 = r3 + r5
            r11.m1569i(r3)
            goto La2
        La0:
            r11.f3791f = r1
        La2:
            r10.f3560j = r2
            return r6
        La5:
            int r8 = r8 + (-4)
            r11.m1561a(r8, r1)
            goto L41
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d.m1508g(b.l.a.a.f1.e, boolean):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        return m1508g(c2003e, true);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }

    public C1976d(int i2, long j2) {
        this.f3552b = i2;
        this.f3553c = j2;
        this.f3554d = new C2360t(10);
        this.f3555e = new C2048o();
        this.f3556f = new C2046m();
        this.f3564n = -9223372036854775807L;
        this.f3557g = new C2047n();
    }
}
