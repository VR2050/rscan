package p005b.p199l.p200a.p201a.p208f1.p209a0;

import java.util.ArrayDeque;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p208f1.C2003e;

/* renamed from: b.l.a.a.f1.a0.a */
/* loaded from: classes.dex */
public final class C1966a implements InterfaceC1968c {

    /* renamed from: a */
    public final byte[] f3418a = new byte[8];

    /* renamed from: b */
    public final ArrayDeque<b> f3419b = new ArrayDeque<>();

    /* renamed from: c */
    public final C1971f f3420c = new C1971f();

    /* renamed from: d */
    public InterfaceC1967b f3421d;

    /* renamed from: e */
    public int f3422e;

    /* renamed from: f */
    public int f3423f;

    /* renamed from: g */
    public long f3424g;

    /* renamed from: b.l.a.a.f1.a0.a$b */
    public static final class b {

        /* renamed from: a */
        public final int f3425a;

        /* renamed from: b */
        public final long f3426b;

        public b(int i2, long j2, a aVar) {
            this.f3425a = i2;
            this.f3426b = j2;
        }
    }

    /* renamed from: a */
    public final long m1472a(C2003e c2003e) {
        c2003e.f3791f = 0;
        while (true) {
            c2003e.m1565e(this.f3418a, 0, 4, false);
            int m1498b = C1971f.m1498b(this.f3418a[0]);
            if (m1498b != -1 && m1498b <= 4) {
                int m1497a = (int) C1971f.m1497a(this.f3418a, m1498b, false);
                Objects.requireNonNull(C1969d.this);
                if (m1497a == 357149030 || m1497a == 524531317 || m1497a == 475249515 || m1497a == 374648427) {
                    c2003e.m1569i(m1498b);
                    return m1497a;
                }
            }
            c2003e.m1569i(1);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:287:0x05a7, code lost:
    
        if (r0 == 0) goto L404;
     */
    /* JADX WARN: Code restructure failed: missing block: B:288:0x078f, code lost:
    
        r5 = r0;
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:383:0x078c, code lost:
    
        if (r0 != 0) goto L403;
     */
    /* JADX WARN: Code restructure failed: missing block: B:390:0x077f, code lost:
    
        if (r0.m2579k() == r2.getLeastSignificantBits()) goto L397;
     */
    /* JADX WARN: Removed duplicated region for block: B:158:0x038a  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x07bc  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x07c6  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x07e9  */
    /* JADX WARN: Removed duplicated region for block: B:273:0x07be  */
    /* JADX WARN: Removed duplicated region for block: B:382:0x0786  */
    /* JADX WARN: Removed duplicated region for block: B:488:0x0a4d  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m1473b(p005b.p199l.p200a.p201a.p208f1.C2003e r42) {
        /*
            Method dump skipped, instructions count: 3226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p209a0.C1966a.m1473b(b.l.a.a.f1.e):boolean");
    }

    /* renamed from: c */
    public final long m1474c(C2003e c2003e, int i2) {
        c2003e.m1568h(this.f3418a, 0, i2, false);
        long j2 = 0;
        for (int i3 = 0; i3 < i2; i3++) {
            j2 = (j2 << 8) | (this.f3418a[i3] & 255);
        }
        return j2;
    }

    /* renamed from: d */
    public final String m1475d(C2003e c2003e, int i2) {
        if (i2 == 0) {
            return "";
        }
        byte[] bArr = new byte[i2];
        c2003e.m1568h(bArr, 0, i2, false);
        while (i2 > 0 && bArr[i2 - 1] == 0) {
            i2--;
        }
        return new String(bArr, 0, i2);
    }
}
