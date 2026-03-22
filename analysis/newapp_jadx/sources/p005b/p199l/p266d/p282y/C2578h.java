package p005b.p199l.p266d.p282y;

import java.util.Map;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.h */
/* loaded from: classes2.dex */
public final class C2578h extends AbstractC2581k {

    /* renamed from: a */
    public static final int[] f7038a = {6, 8, 10, 12, 14};

    /* renamed from: b */
    public static final int[] f7039b = {1, 1, 1, 1};

    /* renamed from: c */
    public static final int[][] f7040c = {new int[]{1, 1, 2}, new int[]{1, 1, 3}};

    /* renamed from: d */
    public static final int[][] f7041d = {new int[]{1, 1, 2, 2, 1}, new int[]{2, 1, 1, 1, 2}, new int[]{1, 2, 1, 1, 2}, new int[]{2, 2, 1, 1, 1}, new int[]{1, 1, 2, 1, 2}, new int[]{2, 1, 2, 1, 1}, new int[]{1, 2, 2, 1, 1}, new int[]{1, 1, 1, 2, 2}, new int[]{2, 1, 1, 2, 1}, new int[]{1, 2, 1, 2, 1}, new int[]{1, 1, 3, 3, 1}, new int[]{3, 1, 1, 1, 3}, new int[]{1, 3, 1, 1, 3}, new int[]{3, 3, 1, 1, 1}, new int[]{1, 1, 3, 1, 3}, new int[]{3, 1, 3, 1, 1}, new int[]{1, 3, 3, 1, 1}, new int[]{1, 1, 1, 3, 3}, new int[]{3, 1, 1, 3, 1}, new int[]{1, 3, 1, 3, 1}};

    /* renamed from: e */
    public int f7042e = -1;

    /* renamed from: g */
    public static int m3010g(int[] iArr) {
        int length = f7041d.length;
        float f2 = 0.38f;
        int i2 = -1;
        for (int i3 = 0; i3 < length; i3++) {
            float m3013d = AbstractC2581k.m3013d(iArr, f7041d[i3], 0.5f);
            if (m3013d < f2) {
                i2 = i3;
                f2 = m3013d;
            } else if (m3013d == f2) {
                i2 = -1;
            }
        }
        if (i2 >= 0) {
            return i2 % 10;
        }
        throw C2529k.f6843f;
    }

    /* renamed from: h */
    public static int[] m3011h(C2543a c2543a, int i2, int[] iArr) {
        int length = iArr.length;
        int[] iArr2 = new int[length];
        int i3 = c2543a.f6892e;
        int i4 = i2;
        boolean z = false;
        int i5 = 0;
        while (i2 < i3) {
            if (c2543a.m2950g(i2) != z) {
                iArr2[i5] = iArr2[i5] + 1;
            } else {
                if (i5 != length - 1) {
                    i5++;
                } else {
                    if (AbstractC2581k.m3013d(iArr2, iArr, 0.5f) < 0.38f) {
                        return new int[]{i4, i2};
                    }
                    i4 += iArr2[0] + iArr2[1];
                    int i6 = i5 - 1;
                    System.arraycopy(iArr2, 2, iArr2, 0, i6);
                    iArr2[i6] = 0;
                    iArr2[i5] = 0;
                    i5 = i6;
                }
                iArr2[i5] = 1;
                z = !z;
            }
            i2++;
        }
        throw C2529k.f6843f;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        int[] m3011h;
        boolean z;
        int i3 = c2543a.f6892e;
        int m2951h = c2543a.m2951h(0);
        if (m2951h == i3) {
            throw C2529k.f6843f;
        }
        int[] m3011h2 = m3011h(c2543a, m2951h, f7039b);
        this.f7042e = (m3011h2[1] - m3011h2[0]) / 4;
        m3012i(c2543a, m3011h2[0]);
        c2543a.m2955m();
        try {
            int i4 = c2543a.f6892e;
            int m2951h2 = c2543a.m2951h(0);
            if (m2951h2 == i4) {
                throw C2529k.f6843f;
            }
            try {
                m3011h = m3011h(c2543a, m2951h2, f7040c[0]);
            } catch (C2529k unused) {
                m3011h = m3011h(c2543a, m2951h2, f7040c[1]);
            }
            m3012i(c2543a, m3011h[0]);
            int i5 = m3011h[0];
            int i6 = c2543a.f6892e;
            m3011h[0] = i6 - m3011h[1];
            m3011h[1] = i6 - i5;
            c2543a.m2955m();
            StringBuilder sb = new StringBuilder(20);
            int i7 = m3011h2[1];
            int i8 = m3011h[0];
            int[] iArr = new int[10];
            int[] iArr2 = new int[5];
            int[] iArr3 = new int[5];
            while (i7 < i8) {
                AbstractC2581k.m3014e(c2543a, i7, iArr);
                for (int i9 = 0; i9 < 5; i9++) {
                    int i10 = i9 * 2;
                    iArr2[i9] = iArr[i10];
                    iArr3[i9] = iArr[i10 + 1];
                }
                sb.append((char) (m3010g(iArr2) + 48));
                sb.append((char) (m3010g(iArr3) + 48));
                for (int i11 = 0; i11 < 10; i11++) {
                    i7 += iArr[i11];
                }
            }
            String sb2 = sb.toString();
            int[] iArr4 = map != null ? (int[]) map.get(EnumC2523e.ALLOWED_LENGTHS) : null;
            if (iArr4 == null) {
                iArr4 = f7038a;
            }
            int length = sb2.length();
            int length2 = iArr4.length;
            int i12 = 0;
            int i13 = 0;
            while (true) {
                if (i12 >= length2) {
                    z = false;
                    break;
                }
                int i14 = iArr4[i12];
                if (length == i14) {
                    z = true;
                    break;
                }
                if (i14 > i13) {
                    i13 = i14;
                }
                i12++;
            }
            if (!z && length > i13) {
                z = true;
            }
            if (!z) {
                throw C2525g.m2925a();
            }
            float f2 = i2;
            return new C2534p(sb2, null, new C2536r[]{new C2536r(m3011h2[1], f2), new C2536r(m3011h[0], f2)}, EnumC2497a.ITF);
        } catch (Throwable th) {
            c2543a.m2955m();
            throw th;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0019, code lost:
    
        return;
     */
    /* renamed from: i */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3012i(p005b.p199l.p266d.p274v.C2543a r3, int r4) {
        /*
            r2 = this;
            int r0 = r2.f7042e
            int r0 = r0 * 10
            if (r0 >= r4) goto L7
            goto L8
        L7:
            r0 = r4
        L8:
            int r4 = r4 + (-1)
            if (r0 <= 0) goto L17
            if (r4 < 0) goto L17
            boolean r1 = r3.m2950g(r4)
            if (r1 != 0) goto L17
            int r0 = r0 + (-1)
            goto L8
        L17:
            if (r0 != 0) goto L1a
            return
        L1a:
            b.l.d.k r3 = p005b.p199l.p266d.C2529k.f6843f
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.C2578h.m3012i(b.l.d.v.a, int):void");
    }
}
