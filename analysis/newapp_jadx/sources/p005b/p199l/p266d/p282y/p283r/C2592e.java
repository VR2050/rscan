package p005b.p199l.p266d.p282y.p283r;

import com.alibaba.fastjson.asm.Opcodes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.e */
/* loaded from: classes2.dex */
public final class C2592e extends AbstractC2588a {

    /* renamed from: g */
    public static final int[] f7079g = {1, 10, 34, 70, 126};

    /* renamed from: h */
    public static final int[] f7080h = {4, 20, 48, 81};

    /* renamed from: i */
    public static final int[] f7081i = {0, Opcodes.IF_ICMPLT, 961, 2015, 2715};

    /* renamed from: j */
    public static final int[] f7082j = {0, 336, 1036, 1516};

    /* renamed from: k */
    public static final int[] f7083k = {8, 6, 4, 3, 1};

    /* renamed from: l */
    public static final int[] f7084l = {2, 4, 6, 8};

    /* renamed from: m */
    public static final int[][] f7085m = {new int[]{3, 8, 2, 1}, new int[]{3, 5, 5, 1}, new int[]{3, 3, 7, 1}, new int[]{3, 1, 9, 1}, new int[]{2, 7, 4, 1}, new int[]{2, 5, 6, 1}, new int[]{2, 3, 8, 1}, new int[]{1, 5, 7, 1}, new int[]{1, 3, 9, 1}};

    /* renamed from: n */
    public final List<C2591d> f7086n = new ArrayList();

    /* renamed from: o */
    public final List<C2591d> f7087o = new ArrayList();

    /* renamed from: k */
    public static void m3030k(Collection<C2591d> collection, C2591d c2591d) {
        if (c2591d == null) {
            return;
        }
        boolean z = false;
        Iterator<C2591d> it = collection.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            C2591d next = it.next();
            if (next.f7072a == c2591d.f7072a) {
                next.f7078d++;
                z = true;
                break;
            }
        }
        if (z) {
            return;
        }
        collection.add(c2591d);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        m3030k(this.f7086n, m3032m(c2543a, false, i2, map));
        c2543a.m2955m();
        m3030k(this.f7087o, m3032m(c2543a, true, i2, map));
        c2543a.m2955m();
        for (C2591d c2591d : this.f7086n) {
            if (c2591d.f7078d > 1) {
                for (C2591d c2591d2 : this.f7087o) {
                    if (c2591d2.f7078d > 1) {
                        int i3 = ((c2591d2.f7073b * 16) + c2591d.f7073b) % 79;
                        int i4 = (c2591d.f7077c.f7074a * 9) + c2591d2.f7077c.f7074a;
                        if (i4 > 72) {
                            i4--;
                        }
                        if (i4 > 8) {
                            i4--;
                        }
                        if (i3 == i4) {
                            String valueOf = String.valueOf((c2591d.f7072a * 4537077) + c2591d2.f7072a);
                            StringBuilder sb = new StringBuilder(14);
                            for (int length = 13 - valueOf.length(); length > 0; length--) {
                                sb.append('0');
                            }
                            sb.append(valueOf);
                            int i5 = 0;
                            for (int i6 = 0; i6 < 13; i6++) {
                                int charAt = sb.charAt(i6) - '0';
                                if ((i6 & 1) == 0) {
                                    charAt *= 3;
                                }
                                i5 += charAt;
                            }
                            int i7 = 10 - (i5 % 10);
                            if (i7 == 10) {
                                i7 = 0;
                            }
                            sb.append(i7);
                            C2536r[] c2536rArr = c2591d.f7077c.f7076c;
                            C2536r[] c2536rArr2 = c2591d2.f7077c.f7076c;
                            return new C2534p(sb.toString(), null, new C2536r[]{c2536rArr[0], c2536rArr[1], c2536rArr2[0], c2536rArr2[1]}, EnumC2497a.RSS_14);
                        }
                    }
                }
            }
        }
        throw C2529k.f6843f;
    }

    /* JADX WARN: Code restructure failed: missing block: B:121:0x00b4, code lost:
    
        r14 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x00b2, code lost:
    
        if (r4 < 4) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x009c, code lost:
    
        if (r4 < 4) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00b6, code lost:
    
        r14 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00b7, code lost:
    
        r15 = false;
     */
    /* renamed from: l */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p266d.p282y.p283r.C2589b m3031l(p005b.p199l.p266d.p274v.C2543a r18, p005b.p199l.p266d.p282y.p283r.C2590c r19, boolean r20) {
        /*
            Method dump skipped, instructions count: 448
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.p283r.C2592e.m3031l(b.l.d.v.a, b.l.d.y.r.c, boolean):b.l.d.y.r.b");
    }

    /* renamed from: m */
    public final C2591d m3032m(C2543a c2543a, boolean z, int i2, Map<EnumC2523e, ?> map) {
        try {
            C2590c m3034o = m3034o(c2543a, i2, z, m3033n(c2543a, z));
            InterfaceC2537s interfaceC2537s = map == null ? null : (InterfaceC2537s) map.get(EnumC2523e.NEED_RESULT_POINT_CALLBACK);
            if (interfaceC2537s != null) {
                float f2 = (r1[0] + r1[1]) / 2.0f;
                if (z) {
                    f2 = (c2543a.f6892e - 1) - f2;
                }
                interfaceC2537s.mo2935a(new C2536r(f2, i2));
            }
            C2589b m3031l = m3031l(c2543a, m3034o, true);
            C2589b m3031l2 = m3031l(c2543a, m3034o, false);
            return new C2591d((m3031l.f7072a * 1597) + m3031l2.f7072a, (m3031l2.f7073b * 4) + m3031l.f7073b, m3034o);
        } catch (C2529k unused) {
            return null;
        }
    }

    /* renamed from: n */
    public final int[] m3033n(C2543a c2543a, boolean z) {
        int[] iArr = this.f7066a;
        iArr[0] = 0;
        iArr[1] = 0;
        iArr[2] = 0;
        iArr[3] = 0;
        int i2 = c2543a.f6892e;
        int i3 = 0;
        boolean z2 = false;
        while (i3 < i2) {
            z2 = !c2543a.m2950g(i3);
            if (z == z2) {
                break;
            }
            i3++;
        }
        int i4 = i3;
        int i5 = 0;
        while (i3 < i2) {
            if (c2543a.m2950g(i3) != z2) {
                iArr[i5] = iArr[i5] + 1;
            } else {
                if (i5 != 3) {
                    i5++;
                } else {
                    if (AbstractC2588a.m3028i(iArr)) {
                        return new int[]{i4, i3};
                    }
                    i4 += iArr[0] + iArr[1];
                    iArr[0] = iArr[2];
                    iArr[1] = iArr[3];
                    iArr[2] = 0;
                    iArr[3] = 0;
                    i5--;
                }
                iArr[i5] = 1;
                z2 = !z2;
            }
            i3++;
        }
        throw C2529k.f6843f;
    }

    /* renamed from: o */
    public final C2590c m3034o(C2543a c2543a, int i2, boolean z, int[] iArr) {
        int i3;
        int i4;
        boolean m2950g = c2543a.m2950g(iArr[0]);
        int i5 = iArr[0] - 1;
        while (i5 >= 0 && m2950g != c2543a.m2950g(i5)) {
            i5--;
        }
        int i6 = i5 + 1;
        int i7 = iArr[0] - i6;
        int[] iArr2 = this.f7066a;
        System.arraycopy(iArr2, 0, iArr2, 1, iArr2.length - 1);
        iArr2[0] = i7;
        int m3029j = AbstractC2588a.m3029j(iArr2, f7085m);
        int i8 = iArr[1];
        if (z) {
            int i9 = c2543a.f6892e;
            i3 = (i9 - 1) - i8;
            i4 = (i9 - 1) - i6;
        } else {
            i3 = i8;
            i4 = i6;
        }
        return new C2590c(m3029j, new int[]{i6, iArr[1]}, i4, i3, i2);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k, p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
        this.f7086n.clear();
        this.f7087o.clear();
    }
}
