package p005b.p199l.p200a.p201a.p208f1.p216x;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.EOFException;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C1993d;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.x.a */
/* loaded from: classes.dex */
public final class C2057a implements InterfaceC2041h {

    /* renamed from: b */
    public static final int[] f4212b;

    /* renamed from: e */
    public static final int f4215e;

    /* renamed from: g */
    public boolean f4217g;

    /* renamed from: h */
    public long f4218h;

    /* renamed from: i */
    public int f4219i;

    /* renamed from: j */
    public int f4220j;

    /* renamed from: k */
    public boolean f4221k;

    /* renamed from: l */
    public long f4222l;

    /* renamed from: n */
    public int f4224n;

    /* renamed from: o */
    public long f4225o;

    /* renamed from: p */
    public InterfaceC2042i f4226p;

    /* renamed from: q */
    public InterfaceC2052s f4227q;

    /* renamed from: r */
    @Nullable
    public InterfaceC2050q f4228r;

    /* renamed from: s */
    public boolean f4229s;

    /* renamed from: a */
    public static final int[] f4211a = {13, 14, 16, 18, 20, 21, 27, 32, 6, 7, 6, 6, 1, 1, 1, 1};

    /* renamed from: c */
    public static final byte[] f4213c = C2344d0.m2342t("#!AMR\n");

    /* renamed from: d */
    public static final byte[] f4214d = C2344d0.m2342t("#!AMR-WB\n");

    /* renamed from: f */
    public final byte[] f4216f = new byte[1];

    /* renamed from: m */
    public int f4223m = -1;

    static {
        int[] iArr = {18, 24, 33, 37, 41, 47, 51, 59, 61, 6, 1, 1, 1, 1, 1, 1};
        f4212b = iArr;
        f4215e = iArr[8];
    }

    public C2057a(int i2) {
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0038, code lost:
    
        if ((!r1 && (r4 < 12 || r4 > 14)) != false) goto L24;
     */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int m1640a(p005b.p199l.p200a.p201a.p208f1.C2003e r4) {
        /*
            r3 = this;
            r0 = 0
            r4.f3791f = r0
            byte[] r1 = r3.f4216f
            r2 = 1
            r4.m1565e(r1, r0, r2, r0)
            byte[] r4 = r3.f4216f
            r4 = r4[r0]
            r1 = r4 & 131(0x83, float:1.84E-43)
            if (r1 > 0) goto L6f
            int r4 = r4 >> 3
            r1 = 15
            r4 = r4 & r1
            if (r4 < 0) goto L3b
            if (r4 > r1) goto L3b
            boolean r1 = r3.f4217g
            if (r1 == 0) goto L28
            r2 = 10
            if (r4 < r2) goto L26
            r2 = 13
            if (r4 <= r2) goto L28
        L26:
            r2 = 1
            goto L29
        L28:
            r2 = 0
        L29:
            if (r2 != 0) goto L3a
            if (r1 != 0) goto L37
            r1 = 12
            if (r4 < r1) goto L35
            r1 = 14
            if (r4 <= r1) goto L37
        L35:
            r1 = 1
            goto L38
        L37:
            r1 = 0
        L38:
            if (r1 == 0) goto L3b
        L3a:
            r0 = 1
        L3b:
            if (r0 != 0) goto L61
            b.l.a.a.l0 r0 = new b.l.a.a.l0
            java.lang.String r1 = "Illegal AMR "
            java.lang.StringBuilder r1 = p005b.p131d.p132a.p133a.C1499a.m586H(r1)
            boolean r2 = r3.f4217g
            if (r2 == 0) goto L4c
            java.lang.String r2 = "WB"
            goto L4e
        L4c:
            java.lang.String r2 = "NB"
        L4e:
            r1.append(r2)
            java.lang.String r2 = " frame type "
            r1.append(r2)
            r1.append(r4)
            java.lang.String r4 = r1.toString()
            r0.<init>(r4)
            throw r0
        L61:
            boolean r0 = r3.f4217g
            if (r0 == 0) goto L6a
            int[] r0 = p005b.p199l.p200a.p201a.p208f1.p216x.C2057a.f4212b
            r4 = r0[r4]
            goto L6e
        L6a:
            int[] r0 = p005b.p199l.p200a.p201a.p208f1.p216x.C2057a.f4211a
            r4 = r0[r4]
        L6e:
            return r4
        L6f:
            b.l.a.a.l0 r0 = new b.l.a.a.l0
            java.lang.String r1 = "Invalid padding bits for frame header "
            java.lang.String r4 = p005b.p131d.p132a.p133a.C1499a.m626l(r1, r4)
            r0.<init>(r4)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p216x.C2057a.m1640a(b.l.a.a.f1.e):int");
    }

    /* renamed from: b */
    public final boolean m1641b(C2003e c2003e) {
        byte[] bArr = f4213c;
        c2003e.f3791f = 0;
        byte[] bArr2 = new byte[bArr.length];
        c2003e.m1565e(bArr2, 0, bArr.length, false);
        if (Arrays.equals(bArr2, bArr)) {
            this.f4217g = false;
            c2003e.m1569i(bArr.length);
            return true;
        }
        byte[] bArr3 = f4214d;
        c2003e.f3791f = 0;
        byte[] bArr4 = new byte[bArr3.length];
        c2003e.m1565e(bArr4, 0, bArr3.length, false);
        if (!Arrays.equals(bArr4, bArr3)) {
            return false;
        }
        this.f4217g = true;
        c2003e.m1569i(bArr3.length);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    public int mo1479d(C2003e c2003e, C2049p c2049p) {
        if (c2003e.f3789d == 0 && !m1641b(c2003e)) {
            throw new C2205l0("Could not find AMR header.");
        }
        if (!this.f4229s) {
            this.f4229s = true;
            boolean z = this.f4217g;
            this.f4227q.mo1615d(Format.m4039z(null, z ? "audio/amr-wb" : "audio/3gpp", null, -1, f4215e, 1, z ? 16000 : 8000, -1, null, null, 0, null));
        }
        int i2 = -1;
        if (this.f4220j == 0) {
            try {
                int m1640a = m1640a(c2003e);
                this.f4219i = m1640a;
                this.f4220j = m1640a;
                if (this.f4223m == -1) {
                    this.f4222l = c2003e.f3789d;
                    this.f4223m = m1640a;
                }
                if (this.f4223m == m1640a) {
                    this.f4224n++;
                }
            } catch (EOFException unused) {
            }
        }
        int mo1612a = this.f4227q.mo1612a(c2003e, this.f4220j, true);
        if (mo1612a != -1) {
            int i3 = this.f4220j - mo1612a;
            this.f4220j = i3;
            i2 = 0;
            if (i3 <= 0) {
                this.f4227q.mo1614c(this.f4218h + this.f4225o, 1, this.f4219i, 0, null);
                this.f4218h += 20000;
            }
        }
        if (!this.f4221k) {
            InterfaceC2050q.b bVar = new InterfaceC2050q.b(-9223372036854775807L, 0L);
            this.f4228r = bVar;
            this.f4226p.mo1623a(bVar);
            this.f4221k = true;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f4226p = interfaceC2042i;
        this.f4227q = interfaceC2042i.mo1625t(0, 1);
        interfaceC2042i.mo1624o();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        this.f4218h = 0L;
        this.f4219i = 0;
        this.f4220j = 0;
        if (j2 != 0) {
            InterfaceC2050q interfaceC2050q = this.f4228r;
            if (interfaceC2050q instanceof C1993d) {
                C1993d c1993d = (C1993d) interfaceC2050q;
                this.f4225o = C1993d.m1544e(j2, c1993d.f3721b, c1993d.f3724e);
                return;
            }
        }
        this.f4225o = 0L;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        return m1641b(c2003e);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
