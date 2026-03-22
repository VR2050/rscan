package p005b.p199l.p266d.p282y;

import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.util.Arrays;
import java.util.Map;
import p005b.p199l.p266d.AbstractC2520b;
import p005b.p199l.p266d.C2521c;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.InterfaceC2532n;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.k */
/* loaded from: classes2.dex */
public abstract class AbstractC2581k implements InterfaceC2532n {
    /* renamed from: d */
    public static float m3013d(int[] iArr, int[] iArr2, float f2) {
        int length = iArr.length;
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < length; i4++) {
            i2 += iArr[i4];
            i3 += iArr2[i4];
        }
        if (i2 < i3) {
            return Float.POSITIVE_INFINITY;
        }
        float f3 = i2;
        float f4 = f3 / i3;
        float f5 = f2 * f4;
        float f6 = 0.0f;
        for (int i5 = 0; i5 < length; i5++) {
            float f7 = iArr2[i5] * f4;
            float f8 = iArr[i5];
            float f9 = f8 > f7 ? f8 - f7 : f7 - f8;
            if (f9 > f5) {
                return Float.POSITIVE_INFINITY;
            }
            f6 += f9;
        }
        return f6 / f3;
    }

    /* renamed from: e */
    public static void m3014e(C2543a c2543a, int i2, int[] iArr) {
        int length = iArr.length;
        int i3 = 0;
        Arrays.fill(iArr, 0, length, 0);
        int i4 = c2543a.f6892e;
        if (i2 >= i4) {
            throw C2529k.f6843f;
        }
        boolean z = !c2543a.m2950g(i2);
        while (i2 < i4) {
            if (c2543a.m2950g(i2) == z) {
                i3++;
                if (i3 == length) {
                    break;
                }
                iArr[i3] = 1;
                z = !z;
            } else {
                iArr[i3] = iArr[i3] + 1;
            }
            i2++;
        }
        if (i3 != length) {
            if (i3 != length - 1 || i2 != i4) {
                throw C2529k.f6843f;
            }
        }
    }

    /* renamed from: f */
    public static void m3015f(C2543a c2543a, int i2, int[] iArr) {
        int length = iArr.length;
        boolean m2950g = c2543a.m2950g(i2);
        while (i2 > 0 && length >= 0) {
            i2--;
            if (c2543a.m2950g(i2) != m2950g) {
                length--;
                m2950g = !m2950g;
            }
        }
        if (length >= 0) {
            throw C2529k.f6843f;
        }
        m3014e(c2543a, i2 + 1, iArr);
    }

    @Override // p005b.p199l.p266d.InterfaceC2532n
    /* renamed from: a */
    public C2534p mo2867a(C2521c c2521c, Map<EnumC2523e, ?> map) {
        EnumC2535q enumC2535q = EnumC2535q.ORIENTATION;
        try {
            return m3016c(c2521c, map);
        } catch (C2529k e2) {
            if (!(map != null && map.containsKey(EnumC2523e.TRY_HARDER)) || !c2521c.f6808a.f6807a.mo2928c()) {
                throw e2;
            }
            AbstractC2520b mo2920a = c2521c.f6808a.mo2920a(c2521c.f6808a.f6807a.mo2929d());
            C2534p m3016c = m3016c(new C2521c(mo2920a), map);
            Map<EnumC2535q, Object> map2 = m3016c.f6858e;
            int i2 = SubsamplingScaleImageView.ORIENTATION_270;
            if (map2 != null && map2.containsKey(enumC2535q)) {
                i2 = (((Integer) map2.get(enumC2535q)).intValue() + SubsamplingScaleImageView.ORIENTATION_270) % 360;
            }
            m3016c.m2933b(enumC2535q, Integer.valueOf(i2));
            C2536r[] c2536rArr = m3016c.f6856c;
            if (c2536rArr != null) {
                int i3 = mo2920a.f6807a.f6839b;
                for (int i4 = 0; i4 < c2536rArr.length; i4++) {
                    c2536rArr[i4] = new C2536r((i3 - c2536rArr[i4].f6872b) - 1.0f, c2536rArr[i4].f6871a);
                }
            }
            return m3016c;
        }
    }

    /* renamed from: b */
    public abstract C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map);

    /* JADX WARN: Removed duplicated region for block: B:35:0x007d A[Catch: o -> 0x00ba, TryCatch #1 {o -> 0x00ba, blocks: (B:33:0x0077, B:35:0x007d, B:37:0x008c), top: B:32:0x0077 }] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00b9 A[SYNTHETIC] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p266d.C2534p m3016c(p005b.p199l.p266d.C2521c r20, java.util.Map<p005b.p199l.p266d.EnumC2523e, ?> r21) {
        /*
            Method dump skipped, instructions count: 219
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.AbstractC2581k.m3016c(b.l.d.c, java.util.Map):b.l.d.p");
    }

    @Override // p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
    }
}
