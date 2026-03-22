package p005b.p199l.p200a.p201a.p208f1.p215g0;

import com.google.android.exoplayer2.Format;
import org.conscrypt.NativeConstants;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.g0.a */
/* loaded from: classes.dex */
public final class C2037a implements InterfaceC2041h {

    /* renamed from: a */
    public InterfaceC2042i f4126a;

    /* renamed from: b */
    public InterfaceC2052s f4127b;

    /* renamed from: c */
    public b f4128c;

    /* renamed from: d */
    public int f4129d = -1;

    /* renamed from: e */
    public long f4130e = -1;

    /* renamed from: b.l.a.a.f1.g0.a$a */
    public static final class a implements b {

        /* renamed from: a */
        public static final int[] f4131a = {-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8};

        /* renamed from: b */
        public static final int[] f4132b = {7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, NativeConstants.EVP_PKEY_EC, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767};

        /* renamed from: c */
        public final InterfaceC2042i f4133c;

        /* renamed from: d */
        public final InterfaceC2052s f4134d;

        /* renamed from: e */
        public final C2038b f4135e;

        /* renamed from: f */
        public final int f4136f;

        /* renamed from: g */
        public final byte[] f4137g;

        /* renamed from: h */
        public final C2360t f4138h;

        /* renamed from: i */
        public final int f4139i;

        /* renamed from: j */
        public final Format f4140j;

        /* renamed from: k */
        public int f4141k;

        /* renamed from: l */
        public long f4142l;

        /* renamed from: m */
        public int f4143m;

        /* renamed from: n */
        public long f4144n;

        public a(InterfaceC2042i interfaceC2042i, InterfaceC2052s interfaceC2052s, C2038b c2038b) {
            this.f4133c = interfaceC2042i;
            this.f4134d = interfaceC2052s;
            this.f4135e = c2038b;
            int max = Math.max(1, c2038b.f4155c / 10);
            this.f4139i = max;
            byte[] bArr = c2038b.f4158f;
            int length = bArr.length;
            byte b2 = bArr[0];
            byte b3 = bArr[1];
            int i2 = ((bArr[3] & 255) << 8) | (bArr[2] & 255);
            this.f4136f = i2;
            int i3 = c2038b.f4154b;
            int i4 = (((c2038b.f4156d - (i3 * 4)) * 8) / (c2038b.f4157e * i3)) + 1;
            if (i2 != i4) {
                throw new C2205l0(C1499a.m629o("Expected frames per block: ", i4, "; got: ", i2));
            }
            int m2327e = C2344d0.m2327e(max, i2);
            this.f4137g = new byte[c2038b.f4156d * m2327e];
            this.f4138h = new C2360t(i2 * 2 * i3 * m2327e);
            int i5 = c2038b.f4155c;
            this.f4140j = Format.m4039z(null, "audio/raw", null, ((c2038b.f4156d * i5) * 8) / i2, max * 2 * i3, c2038b.f4154b, i5, 2, null, null, 0, null);
        }

        /* JADX WARN: Removed duplicated region for block: B:12:0x0043 A[LOOP:0: B:6:0x0028->B:12:0x0043, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:13:0x0041 A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:17:0x0052  */
        /* JADX WARN: Removed duplicated region for block: B:49:0x015b  */
        /* JADX WARN: Removed duplicated region for block: B:8:0x002b  */
        /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:10:0x003f -> B:4:0x0041). Please report as a decompilation issue!!! */
        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean mo1616a(p005b.p199l.p200a.p201a.p208f1.C2003e r19, long r20) {
            /*
                Method dump skipped, instructions count: 363
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.a.mo1616a(b.l.a.a.f1.e, long):boolean");
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: b */
        public void mo1617b(long j2) {
            this.f4141k = 0;
            this.f4142l = j2;
            this.f4143m = 0;
            this.f4144n = 0L;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: c */
        public void mo1618c(int i2, long j2) {
            this.f4133c.mo1623a(new C2040d(this.f4135e, this.f4136f, i2, j2));
            this.f4134d.mo1615d(this.f4140j);
        }

        /* renamed from: d */
        public final int m1619d(int i2) {
            return i2 / (this.f4135e.f4154b * 2);
        }

        /* renamed from: e */
        public final void m1620e(int i2) {
            long m2314F = this.f4142l + C2344d0.m2314F(this.f4144n, 1000000L, this.f4135e.f4155c);
            int i3 = i2 * 2 * this.f4135e.f4154b;
            this.f4134d.mo1614c(m2314F, 1, i3, this.f4143m - i3, null);
            this.f4144n += i2;
            this.f4143m -= i3;
        }
    }

    /* renamed from: b.l.a.a.f1.g0.a$b */
    public interface b {
        /* renamed from: a */
        boolean mo1616a(C2003e c2003e, long j2);

        /* renamed from: b */
        void mo1617b(long j2);

        /* renamed from: c */
        void mo1618c(int i2, long j2);
    }

    /* renamed from: b.l.a.a.f1.g0.a$c */
    public static final class c implements b {

        /* renamed from: a */
        public final InterfaceC2042i f4145a;

        /* renamed from: b */
        public final InterfaceC2052s f4146b;

        /* renamed from: c */
        public final C2038b f4147c;

        /* renamed from: d */
        public final Format f4148d;

        /* renamed from: e */
        public final int f4149e;

        /* renamed from: f */
        public long f4150f;

        /* renamed from: g */
        public int f4151g;

        /* renamed from: h */
        public long f4152h;

        public c(InterfaceC2042i interfaceC2042i, InterfaceC2052s interfaceC2052s, C2038b c2038b, String str, int i2) {
            this.f4145a = interfaceC2042i;
            this.f4146b = interfaceC2052s;
            this.f4147c = c2038b;
            int i3 = (c2038b.f4154b * c2038b.f4157e) / 8;
            if (c2038b.f4156d != i3) {
                StringBuilder m588J = C1499a.m588J("Expected block size: ", i3, "; got: ");
                m588J.append(c2038b.f4156d);
                throw new C2205l0(m588J.toString());
            }
            int max = Math.max(i3, (c2038b.f4155c * i3) / 10);
            this.f4149e = max;
            int i4 = c2038b.f4155c;
            this.f4148d = Format.m4039z(null, str, null, i3 * i4 * 8, max, c2038b.f4154b, i4, i2, null, null, 0, null);
        }

        /* JADX WARN: Removed duplicated region for block: B:16:0x003f  */
        /* JADX WARN: Removed duplicated region for block: B:7:0x0018  */
        /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:9:0x002c -> B:4:0x002e). Please report as a decompilation issue!!! */
        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean mo1616a(p005b.p199l.p200a.p201a.p208f1.C2003e r18, long r19) {
            /*
                r17 = this;
                r0 = 1
                r1 = 0
                int r3 = (r19 > r1 ? 1 : (r19 == r1 ? 0 : -1))
                if (r3 != 0) goto Le
                r5 = r17
                r1 = r18
                r2 = r19
                goto L2e
            Le:
                r1 = 0
                r5 = r17
                r1 = r18
                r2 = r19
                r4 = 0
            L16:
                if (r4 != 0) goto L36
                int r6 = r5.f4151g
                int r7 = r5.f4149e
                if (r6 >= r7) goto L36
                int r7 = r7 - r6
                long r6 = (long) r7
                long r6 = java.lang.Math.min(r6, r2)
                int r7 = (int) r6
                b.l.a.a.f1.s r6 = r5.f4146b
                int r6 = r6.mo1612a(r1, r7, r0)
                r7 = -1
                if (r6 != r7) goto L30
            L2e:
                r4 = 1
                goto L16
            L30:
                int r7 = r5.f4151g
                int r7 = r7 + r6
                r5.f4151g = r7
                goto L16
            L36:
                b.l.a.a.f1.g0.b r0 = r5.f4147c
                int r1 = r0.f4156d
                int r2 = r5.f4151g
                int r2 = r2 / r1
                if (r2 <= 0) goto L65
                long r6 = r5.f4150f
                long r8 = r5.f4152h
                r10 = 1000000(0xf4240, double:4.940656E-318)
                int r0 = r0.f4155c
                long r12 = (long) r0
                long r8 = p005b.p199l.p200a.p201a.p250p1.C2344d0.m2314F(r8, r10, r12)
                long r11 = r6 + r8
                int r14 = r2 * r1
                int r0 = r5.f4151g
                int r0 = r0 - r14
                b.l.a.a.f1.s r10 = r5.f4146b
                r13 = 1
                r16 = 0
                r15 = r0
                r10.mo1614c(r11, r13, r14, r15, r16)
                long r6 = r5.f4152h
                long r1 = (long) r2
                long r6 = r6 + r1
                r5.f4152h = r6
                r5.f4151g = r0
            L65:
                return r4
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.c.mo1616a(b.l.a.a.f1.e, long):boolean");
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: b */
        public void mo1617b(long j2) {
            this.f4150f = j2;
            this.f4151g = 0;
            this.f4152h = 0L;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.b
        /* renamed from: c */
        public void mo1618c(int i2, long j2) {
            this.f4145a.mo1623a(new C2040d(this.f4147c, 1, i2, j2));
            this.f4146b.mo1615d(this.f4148d);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0079  */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r13, p005b.p199l.p200a.p201a.p208f1.C2049p r14) {
        /*
            Method dump skipped, instructions count: 325
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p215g0.C2037a.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f4126a = interfaceC2042i;
        this.f4127b = interfaceC2042i.mo1625t(0, 1);
        interfaceC2042i.mo1624o();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    public void mo1481f(long j2, long j3) {
        b bVar = this.f4128c;
        if (bVar != null) {
            bVar.mo1617b(j3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        return C4195m.m4756A0(c2003e) != null;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
