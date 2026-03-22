package p005b.p199l.p200a.p201a.p208f1.p211c0;

import android.util.SparseArray;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a;
import p005b.p199l.p200a.p201a.p220h1.p221g.C2085b;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.c0.d */
/* loaded from: classes.dex */
public class C1984d implements InterfaceC2041h {

    /* renamed from: a */
    public static final byte[] f3602a = {-94, 57, 79, 82, 90, -101, 79, 20, -94, 68, 108, 66, 124, 100, -115, -12};

    /* renamed from: b */
    public static final Format f3603b = Format.m4027D(null, "application/x-emsg", Long.MAX_VALUE);

    /* renamed from: A */
    public long f3604A;

    /* renamed from: B */
    public b f3605B;

    /* renamed from: C */
    public int f3606C;

    /* renamed from: D */
    public int f3607D;

    /* renamed from: E */
    public int f3608E;

    /* renamed from: F */
    public boolean f3609F;

    /* renamed from: G */
    public InterfaceC2042i f3610G;

    /* renamed from: H */
    public InterfaceC2052s[] f3611H;

    /* renamed from: I */
    public InterfaceC2052s[] f3612I;

    /* renamed from: J */
    public boolean f3613J;

    /* renamed from: c */
    public final int f3614c;

    /* renamed from: d */
    @Nullable
    public final C1989i f3615d;

    /* renamed from: e */
    public final List<Format> f3616e;

    /* renamed from: f */
    public final SparseArray<b> f3617f;

    /* renamed from: g */
    public final C2360t f3618g;

    /* renamed from: h */
    public final C2360t f3619h;

    /* renamed from: i */
    public final C2360t f3620i;

    /* renamed from: j */
    public final byte[] f3621j;

    /* renamed from: k */
    public final C2360t f3622k;

    /* renamed from: l */
    @Nullable
    public final C2342c0 f3623l;

    /* renamed from: m */
    public final C2085b f3624m;

    /* renamed from: n */
    public final C2360t f3625n;

    /* renamed from: o */
    public final ArrayDeque<AbstractC1981a.a> f3626o;

    /* renamed from: p */
    public final ArrayDeque<a> f3627p;

    /* renamed from: q */
    @Nullable
    public final InterfaceC2052s f3628q;

    /* renamed from: r */
    public int f3629r;

    /* renamed from: s */
    public int f3630s;

    /* renamed from: t */
    public long f3631t;

    /* renamed from: u */
    public int f3632u;

    /* renamed from: v */
    public C2360t f3633v;

    /* renamed from: w */
    public long f3634w;

    /* renamed from: x */
    public int f3635x;

    /* renamed from: y */
    public long f3636y;

    /* renamed from: z */
    public long f3637z;

    /* renamed from: b.l.a.a.f1.c0.d$a */
    public static final class a {

        /* renamed from: a */
        public final long f3638a;

        /* renamed from: b */
        public final int f3639b;

        public a(long j2, int i2) {
            this.f3638a = j2;
            this.f3639b = i2;
        }
    }

    /* renamed from: b.l.a.a.f1.c0.d$b */
    public static final class b {

        /* renamed from: a */
        public final InterfaceC2052s f3640a;

        /* renamed from: d */
        public C1989i f3643d;

        /* renamed from: e */
        public C1983c f3644e;

        /* renamed from: f */
        public int f3645f;

        /* renamed from: g */
        public int f3646g;

        /* renamed from: h */
        public int f3647h;

        /* renamed from: i */
        public int f3648i;

        /* renamed from: b */
        public final C1991k f3641b = new C1991k();

        /* renamed from: c */
        public final C2360t f3642c = new C2360t();

        /* renamed from: j */
        public final C2360t f3649j = new C2360t(1);

        /* renamed from: k */
        public final C2360t f3650k = new C2360t();

        public b(InterfaceC2052s interfaceC2052s) {
            this.f3640a = interfaceC2052s;
        }

        /* renamed from: a */
        public final C1990j m1525a() {
            C1991k c1991k = this.f3641b;
            int i2 = c1991k.f3694a.f3598a;
            C1990j c1990j = c1991k.f3707n;
            if (c1990j == null) {
                c1990j = this.f3643d.m1540a(i2);
            }
            if (c1990j == null || !c1990j.f3689a) {
                return null;
            }
            return c1990j;
        }

        /* renamed from: b */
        public void m1526b(C1989i c1989i, C1983c c1983c) {
            Objects.requireNonNull(c1989i);
            this.f3643d = c1989i;
            Objects.requireNonNull(c1983c);
            this.f3644e = c1983c;
            this.f3640a.mo1615d(c1989i.f3683f);
            m1529e();
        }

        /* renamed from: c */
        public boolean m1527c() {
            this.f3645f++;
            int i2 = this.f3646g + 1;
            this.f3646g = i2;
            int[] iArr = this.f3641b.f3700g;
            int i3 = this.f3647h;
            if (i2 != iArr[i3]) {
                return true;
            }
            this.f3647h = i3 + 1;
            this.f3646g = 0;
            return false;
        }

        /* renamed from: d */
        public int m1528d(int i2, int i3) {
            C2360t c2360t;
            C1990j m1525a = m1525a();
            if (m1525a == null) {
                return 0;
            }
            int i4 = m1525a.f3692d;
            if (i4 != 0) {
                c2360t = this.f3641b.f3709p;
            } else {
                byte[] bArr = m1525a.f3693e;
                C2360t c2360t2 = this.f3650k;
                int length = bArr.length;
                c2360t2.f6133a = bArr;
                c2360t2.f6135c = length;
                c2360t2.f6134b = 0;
                i4 = bArr.length;
                c2360t = c2360t2;
            }
            C1991k c1991k = this.f3641b;
            boolean z = c1991k.f3705l && c1991k.f3706m[this.f3645f];
            boolean z2 = z || i3 != 0;
            C2360t c2360t3 = this.f3649j;
            c2360t3.f6133a[0] = (byte) ((z2 ? 128 : 0) | i4);
            c2360t3.m2567C(0);
            this.f3640a.mo1613b(this.f3649j, 1);
            this.f3640a.mo1613b(c2360t, i4);
            if (!z2) {
                return i4 + 1;
            }
            if (!z) {
                this.f3642c.m2593y(8);
                C2360t c2360t4 = this.f3642c;
                byte[] bArr2 = c2360t4.f6133a;
                bArr2[0] = 0;
                bArr2[1] = 1;
                bArr2[2] = (byte) ((i3 >> 8) & 255);
                bArr2[3] = (byte) (i3 & 255);
                bArr2[4] = (byte) ((i2 >> 24) & 255);
                bArr2[5] = (byte) ((i2 >> 16) & 255);
                bArr2[6] = (byte) ((i2 >> 8) & 255);
                bArr2[7] = (byte) (i2 & 255);
                this.f3640a.mo1613b(c2360t4, 8);
                return i4 + 1 + 8;
            }
            C2360t c2360t5 = this.f3641b.f3709p;
            int m2590v = c2360t5.m2590v();
            c2360t5.m2568D(-2);
            int i5 = (m2590v * 6) + 2;
            if (i3 != 0) {
                this.f3642c.m2593y(i5);
                this.f3642c.m2572d(c2360t5.f6133a, 0, i5);
                c2360t5.m2568D(i5);
                c2360t5 = this.f3642c;
                byte[] bArr3 = c2360t5.f6133a;
                int i6 = (((bArr3[2] & 255) << 8) | (bArr3[3] & 255)) + i3;
                bArr3[2] = (byte) ((i6 >> 8) & 255);
                bArr3[3] = (byte) (i6 & 255);
            }
            this.f3640a.mo1613b(c2360t5, i5);
            return i4 + 1 + i5;
        }

        /* renamed from: e */
        public void m1529e() {
            C1991k c1991k = this.f3641b;
            c1991k.f3697d = 0;
            c1991k.f3711r = 0L;
            c1991k.f3705l = false;
            c1991k.f3710q = false;
            c1991k.f3707n = null;
            this.f3645f = 0;
            this.f3647h = 0;
            this.f3646g = 0;
            this.f3648i = 0;
        }
    }

    public C1984d(int i2, @Nullable C2342c0 c2342c0, @Nullable C1989i c1989i, List<Format> list) {
        this(i2, c2342c0, c1989i, list, null);
    }

    @Nullable
    /* renamed from: c */
    public static DrmInitData m1519c(List<AbstractC1981a.b> list) {
        int size = list.size();
        ArrayList arrayList = null;
        for (int i2 = 0; i2 < size; i2++) {
            AbstractC1981a.b bVar = list.get(i2);
            if (bVar.f3584a == 1886614376) {
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                byte[] bArr = bVar.f3588b.f6133a;
                UUID m4845z0 = C4195m.m4845z0(bArr);
                if (m4845z0 != null) {
                    arrayList.add(new DrmInitData.SchemeData(m4845z0, null, "video/mp4", bArr));
                }
            }
        }
        if (arrayList == null) {
            return null;
        }
        return new DrmInitData(null, false, (DrmInitData.SchemeData[]) arrayList.toArray(new DrmInitData.SchemeData[0]));
    }

    /* renamed from: i */
    public static void m1520i(C2360t c2360t, int i2, C1991k c1991k) {
        c2360t.m2567C(i2 + 8);
        int m2573e = c2360t.m2573e() & ViewCompat.MEASURED_SIZE_MASK;
        if ((m2573e & 1) != 0) {
            throw new C2205l0("Overriding TrackEncryptionBox parameters is unsupported.");
        }
        boolean z = (m2573e & 2) != 0;
        int m2588t = c2360t.m2588t();
        if (m2588t != c1991k.f3698e) {
            StringBuilder m588J = C1499a.m588J("Length mismatch: ", m2588t, ", ");
            m588J.append(c1991k.f3698e);
            throw new C2205l0(m588J.toString());
        }
        Arrays.fill(c1991k.f3706m, 0, m2588t, z);
        c1991k.m1541a(c2360t.m2569a());
        c2360t.m2572d(c1991k.f3709p.f6133a, 0, c1991k.f3708o);
        c1991k.f3709p.m2567C(0);
        c1991k.f3710q = false;
    }

    /* renamed from: a */
    public final void m1521a() {
        this.f3629r = 0;
        this.f3632u = 0;
    }

    /* renamed from: b */
    public final C1983c m1522b(SparseArray<C1983c> sparseArray, int i2) {
        if (sparseArray.size() == 1) {
            return sparseArray.valueAt(0);
        }
        C1983c c1983c = sparseArray.get(i2);
        Objects.requireNonNull(c1983c);
        return c1983c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:11:0x06e3 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0004 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:238:0x02a7 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:240:0x0004 A[SYNTHETIC] */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r29, p005b.p199l.p200a.p201a.p208f1.C2049p r30) {
        /*
            Method dump skipped, instructions count: 1781
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f3610G = interfaceC2042i;
        C1989i c1989i = this.f3615d;
        if (c1989i != null) {
            b bVar = new b(interfaceC2042i.mo1625t(0, c1989i.f3679b));
            bVar.m1526b(this.f3615d, new C1983c(0, 0, 0, 0));
            this.f3617f.put(0, bVar);
            m1523g();
            this.f3610G.mo1624o();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        int size = this.f3617f.size();
        for (int i2 = 0; i2 < size; i2++) {
            this.f3617f.valueAt(i2).m1529e();
        }
        this.f3627p.clear();
        this.f3635x = 0;
        this.f3636y = j3;
        this.f3626o.clear();
        m1521a();
    }

    /* renamed from: g */
    public final void m1523g() {
        int i2;
        if (this.f3611H == null) {
            InterfaceC2052s[] interfaceC2052sArr = new InterfaceC2052s[2];
            this.f3611H = interfaceC2052sArr;
            InterfaceC2052s interfaceC2052s = this.f3628q;
            if (interfaceC2052s != null) {
                interfaceC2052sArr[0] = interfaceC2052s;
                i2 = 1;
            } else {
                i2 = 0;
            }
            if ((this.f3614c & 4) != 0) {
                interfaceC2052sArr[i2] = this.f3610G.mo1625t(this.f3617f.size(), 4);
                i2++;
            }
            InterfaceC2052s[] interfaceC2052sArr2 = (InterfaceC2052s[]) Arrays.copyOf(this.f3611H, i2);
            this.f3611H = interfaceC2052sArr2;
            for (InterfaceC2052s interfaceC2052s2 : interfaceC2052sArr2) {
                interfaceC2052s2.mo1615d(f3603b);
            }
        }
        if (this.f3612I == null) {
            this.f3612I = new InterfaceC2052s[this.f3616e.size()];
            for (int i3 = 0; i3 < this.f3612I.length; i3++) {
                InterfaceC2052s mo1625t = this.f3610G.mo1625t(this.f3617f.size() + 1 + i3, 3);
                mo1625t.mo1615d(this.f3616e.get(i3));
                this.f3612I[i3] = mo1625t;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        return C1988h.m1539a(c2003e, true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0397  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x03a8  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x039e  */
    /* JADX WARN: Type inference failed for: r1v41 */
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1524j(long r50) {
        /*
            Method dump skipped, instructions count: 1860
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d.m1524j(long):void");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }

    public C1984d(int i2, @Nullable C2342c0 c2342c0, @Nullable C1989i c1989i, List<Format> list, @Nullable InterfaceC2052s interfaceC2052s) {
        this.f3614c = i2 | (c1989i != null ? 8 : 0);
        this.f3623l = c2342c0;
        this.f3615d = c1989i;
        this.f3616e = Collections.unmodifiableList(list);
        this.f3628q = interfaceC2052s;
        this.f3624m = new C2085b();
        this.f3625n = new C2360t(16);
        this.f3618g = new C2360t(C2358r.f6109a);
        this.f3619h = new C2360t(5);
        this.f3620i = new C2360t();
        byte[] bArr = new byte[16];
        this.f3621j = bArr;
        this.f3622k = new C2360t(bArr);
        this.f3626o = new ArrayDeque<>();
        this.f3627p = new ArrayDeque<>();
        this.f3617f = new SparseArray<>();
        this.f3637z = -9223372036854775807L;
        this.f3636y = -9223372036854775807L;
        this.f3604A = -9223372036854775807L;
        m1521a();
    }
}
