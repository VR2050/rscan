package p005b.p199l.p266d.p282y;

import java.util.Arrays;
import java.util.Map;
import p005b.p199l.p266d.AbstractC2533o;
import p005b.p199l.p266d.C2522d;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.p */
/* loaded from: classes2.dex */
public abstract class AbstractC2586p extends AbstractC2581k {

    /* renamed from: a */
    public static final int[] f7056a = {1, 1, 1};

    /* renamed from: b */
    public static final int[] f7057b = {1, 1, 1, 1, 1};

    /* renamed from: c */
    public static final int[][] f7058c;

    /* renamed from: d */
    public static final int[][] f7059d;

    /* renamed from: e */
    public final StringBuilder f7060e = new StringBuilder(20);

    /* renamed from: f */
    public final C2585o f7061f = new C2585o();

    /* renamed from: g */
    public final C2577g f7062g = new C2577g();

    static {
        int[][] iArr = {new int[]{3, 2, 1, 1}, new int[]{2, 2, 2, 1}, new int[]{2, 1, 2, 2}, new int[]{1, 4, 1, 1}, new int[]{1, 1, 3, 2}, new int[]{1, 2, 3, 1}, new int[]{1, 1, 1, 4}, new int[]{1, 3, 1, 2}, new int[]{1, 2, 1, 3}, new int[]{3, 1, 1, 2}};
        f7058c = iArr;
        int[][] iArr2 = new int[20][];
        f7059d = iArr2;
        System.arraycopy(iArr, 0, iArr2, 0, 10);
        for (int i2 = 10; i2 < 20; i2++) {
            int[] iArr3 = f7058c[i2 - 10];
            int[] iArr4 = new int[iArr3.length];
            for (int i3 = 0; i3 < iArr3.length; i3++) {
                iArr4[i3] = iArr3[(iArr3.length - i3) - 1];
            }
            f7059d[i2] = iArr4;
        }
    }

    /* renamed from: h */
    public static int m3021h(C2543a c2543a, int[] iArr, int i2, int[][] iArr2) {
        AbstractC2581k.m3014e(c2543a, i2, iArr);
        int length = iArr2.length;
        float f2 = 0.48f;
        int i3 = -1;
        for (int i4 = 0; i4 < length; i4++) {
            float m3013d = AbstractC2581k.m3013d(iArr, iArr2[i4], 0.7f);
            if (m3013d < f2) {
                i3 = i4;
                f2 = m3013d;
            }
        }
        if (i3 >= 0) {
            return i3;
        }
        throw C2529k.f6843f;
    }

    /* renamed from: l */
    public static int[] m3022l(C2543a c2543a, int i2, boolean z, int[] iArr, int[] iArr2) {
        int i3 = c2543a.f6892e;
        int m2952i = z ? c2543a.m2952i(i2) : c2543a.m2951h(i2);
        int length = iArr.length;
        boolean z2 = z;
        int i4 = 0;
        int i5 = m2952i;
        while (m2952i < i3) {
            if (c2543a.m2950g(m2952i) != z2) {
                iArr2[i4] = iArr2[i4] + 1;
            } else {
                if (i4 != length - 1) {
                    i4++;
                } else {
                    if (AbstractC2581k.m3013d(iArr2, iArr, 0.7f) < 0.48f) {
                        return new int[]{i5, m2952i};
                    }
                    i5 += iArr2[0] + iArr2[1];
                    int i6 = i4 - 1;
                    System.arraycopy(iArr2, 2, iArr2, 0, i6);
                    iArr2[i6] = 0;
                    iArr2[i4] = 0;
                    i4 = i6;
                }
                iArr2[i4] = 1;
                z2 = !z2;
            }
            m2952i++;
        }
        throw C2529k.f6843f;
    }

    /* renamed from: m */
    public static int[] m3023m(C2543a c2543a) {
        int[] iArr = new int[f7056a.length];
        int[] iArr2 = null;
        boolean z = false;
        int i2 = 0;
        while (!z) {
            int[] iArr3 = f7056a;
            Arrays.fill(iArr, 0, iArr3.length, 0);
            iArr2 = m3022l(c2543a, i2, false, iArr3, iArr);
            int i3 = iArr2[0];
            int i4 = iArr2[1];
            int i5 = i3 - (i4 - i3);
            if (i5 >= 0) {
                z = c2543a.m2954l(i5, i3, false);
            }
            i2 = i4;
        }
        return iArr2;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        return mo3018k(i2, c2543a, m3023m(c2543a), map);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x004c, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo3024g(java.lang.String r10) {
        /*
            r9 = this;
            int r0 = r10.length()
            r1 = 0
            if (r0 != 0) goto L8
            goto L53
        L8:
            r2 = 1
            int r0 = r0 - r2
            char r3 = r10.charAt(r0)
            r4 = 10
            int r3 = java.lang.Character.digit(r3, r4)
            java.lang.CharSequence r10 = r10.subSequence(r1, r0)
            int r0 = r10.length()
            int r5 = r0 + (-1)
            r6 = 0
        L1f:
            r7 = 9
            if (r5 < 0) goto L36
            char r8 = r10.charAt(r5)
            int r8 = r8 + (-48)
            if (r8 < 0) goto L31
            if (r8 > r7) goto L31
            int r6 = r6 + r8
            int r5 = r5 + (-2)
            goto L1f
        L31:
            b.l.d.g r10 = p005b.p199l.p266d.C2525g.m2925a()
            throw r10
        L36:
            int r6 = r6 * 3
        L38:
            int r0 = r0 + (-2)
            if (r0 < 0) goto L4d
            char r5 = r10.charAt(r0)
            int r5 = r5 + (-48)
            if (r5 < 0) goto L48
            if (r5 > r7) goto L48
            int r6 = r6 + r5
            goto L38
        L48:
            b.l.d.g r10 = p005b.p199l.p266d.C2525g.m2925a()
            throw r10
        L4d:
            int r10 = 1000 - r6
            int r10 = r10 % r4
            if (r10 != r3) goto L53
            r1 = 1
        L53:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.AbstractC2586p.mo3024g(java.lang.String):boolean");
    }

    /* renamed from: i */
    public int[] mo3025i(C2543a c2543a, int i2) {
        int[] iArr = f7056a;
        return m3022l(c2543a, i2, false, iArr, new int[iArr.length]);
    }

    /* renamed from: j */
    public abstract int mo3006j(C2543a c2543a, int[] iArr, StringBuilder sb);

    /* renamed from: k */
    public C2534p mo3018k(int i2, C2543a c2543a, int[] iArr, Map<EnumC2523e, ?> map) {
        int i3;
        boolean z;
        String str = null;
        InterfaceC2537s interfaceC2537s = map == null ? null : (InterfaceC2537s) map.get(EnumC2523e.NEED_RESULT_POINT_CALLBACK);
        if (interfaceC2537s != null) {
            interfaceC2537s.mo2935a(new C2536r((iArr[0] + iArr[1]) / 2.0f, i2));
        }
        StringBuilder sb = this.f7060e;
        sb.setLength(0);
        int mo3006j = mo3006j(c2543a, iArr, sb);
        if (interfaceC2537s != null) {
            interfaceC2537s.mo2935a(new C2536r(mo3006j, i2));
        }
        int[] mo3025i = mo3025i(c2543a, mo3006j);
        if (interfaceC2537s != null) {
            interfaceC2537s.mo2935a(new C2536r((mo3025i[0] + mo3025i[1]) / 2.0f, i2));
        }
        int i4 = mo3025i[1];
        int i5 = (i4 - mo3025i[0]) + i4;
        if (i5 >= c2543a.f6892e || !c2543a.m2954l(i4, i5, false)) {
            throw C2529k.f6843f;
        }
        String sb2 = sb.toString();
        if (sb2.length() < 8) {
            throw C2525g.m2925a();
        }
        if (!mo3024g(sb2)) {
            throw C2522d.m2924a();
        }
        EnumC2497a mo3007n = mo3007n();
        float f2 = i2;
        C2534p c2534p = new C2534p(sb2, null, new C2536r[]{new C2536r((iArr[1] + iArr[0]) / 2.0f, f2), new C2536r((mo3025i[1] + mo3025i[0]) / 2.0f, f2)}, mo3007n);
        try {
            C2534p m3020a = this.f7061f.m3020a(i2, c2543a, mo3025i[1]);
            c2534p.m2933b(EnumC2535q.UPC_EAN_EXTENSION, m3020a.f6854a);
            c2534p.m2932a(m3020a.f6858e);
            C2536r[] c2536rArr = m3020a.f6856c;
            C2536r[] c2536rArr2 = c2534p.f6856c;
            if (c2536rArr2 == null) {
                c2534p.f6856c = c2536rArr;
            } else if (c2536rArr != null && c2536rArr.length > 0) {
                C2536r[] c2536rArr3 = new C2536r[c2536rArr2.length + c2536rArr.length];
                System.arraycopy(c2536rArr2, 0, c2536rArr3, 0, c2536rArr2.length);
                System.arraycopy(c2536rArr, 0, c2536rArr3, c2536rArr2.length, c2536rArr.length);
                c2534p.f6856c = c2536rArr3;
            }
            i3 = m3020a.f6854a.length();
        } catch (AbstractC2533o unused) {
            i3 = 0;
        }
        int[] iArr2 = map == null ? null : (int[]) map.get(EnumC2523e.ALLOWED_EAN_EXTENSIONS);
        if (iArr2 != null) {
            int length = iArr2.length;
            int i6 = 0;
            while (true) {
                if (i6 >= length) {
                    z = false;
                    break;
                }
                if (i3 == iArr2[i6]) {
                    z = true;
                    break;
                }
                i6++;
            }
            if (!z) {
                throw C2529k.f6843f;
            }
        }
        if (mo3007n == EnumC2497a.EAN_13 || mo3007n == EnumC2497a.UPC_A) {
            C2577g c2577g = this.f7062g;
            c2577g.m3009b();
            int parseInt = Integer.parseInt(sb2.substring(0, 3));
            int size = c2577g.f7036a.size();
            int i7 = 0;
            while (true) {
                if (i7 < size) {
                    int[] iArr3 = c2577g.f7036a.get(i7);
                    int i8 = iArr3[0];
                    if (parseInt < i8) {
                        break;
                    }
                    if (iArr3.length != 1) {
                        i8 = iArr3[1];
                    }
                    if (parseInt <= i8) {
                        str = c2577g.f7037b.get(i7);
                        break;
                    }
                    i7++;
                } else {
                    break;
                }
            }
            if (str != null) {
                c2534p.m2933b(EnumC2535q.POSSIBLE_COUNTRY, str);
            }
        }
        return c2534p;
    }

    /* renamed from: n */
    public abstract EnumC2497a mo3007n();
}
