package p005b.p199l.p266d.p286z.p287d;

import java.lang.reflect.Array;
import p005b.p199l.p266d.p286z.C2615a;

/* renamed from: b.l.d.z.d.i */
/* loaded from: classes2.dex */
public final class C2626i {

    /* renamed from: a */
    public static final float[][] f7162a = (float[][]) Array.newInstance((Class<?>) float.class, C2615a.f7128b.length, 8);

    static {
        int i2;
        int i3 = 0;
        while (true) {
            int[] iArr = C2615a.f7128b;
            if (i3 >= iArr.length) {
                return;
            }
            int i4 = iArr[i3];
            int i5 = i4 & 1;
            int i6 = 0;
            while (i6 < 8) {
                float f2 = 0.0f;
                while (true) {
                    i2 = i4 & 1;
                    if (i2 == i5) {
                        f2 += 1.0f;
                        i4 >>= 1;
                    }
                }
                f7162a[i3][(8 - i6) - 1] = f2 / 17.0f;
                i6++;
                i5 = i2;
            }
            i3++;
        }
    }
}
