package p005b.p199l.p200a.p201a.p251q1;

import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.q1.j */
/* loaded from: classes.dex */
public final class C2378j {

    /* renamed from: a */
    @Nullable
    public final List<byte[]> f6184a;

    /* renamed from: b */
    public final int f6185b;

    public C2378j(@Nullable List<byte[]> list, int i2) {
        this.f6184a = list;
        this.f6185b = i2;
    }

    /* renamed from: a */
    public static C2378j m2615a(C2360t c2360t) {
        try {
            c2360t.m2568D(21);
            int m2585q = c2360t.m2585q() & 3;
            int m2585q2 = c2360t.m2585q();
            int i2 = c2360t.f6134b;
            int i3 = 0;
            for (int i4 = 0; i4 < m2585q2; i4++) {
                c2360t.m2568D(1);
                int m2590v = c2360t.m2590v();
                for (int i5 = 0; i5 < m2590v; i5++) {
                    int m2590v2 = c2360t.m2590v();
                    i3 += m2590v2 + 4;
                    c2360t.m2568D(m2590v2);
                }
            }
            c2360t.m2567C(i2);
            byte[] bArr = new byte[i3];
            int i6 = 0;
            for (int i7 = 0; i7 < m2585q2; i7++) {
                c2360t.m2568D(1);
                int m2590v3 = c2360t.m2590v();
                for (int i8 = 0; i8 < m2590v3; i8++) {
                    int m2590v4 = c2360t.m2590v();
                    byte[] bArr2 = C2358r.f6109a;
                    System.arraycopy(bArr2, 0, bArr, i6, bArr2.length);
                    int length = i6 + bArr2.length;
                    System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, length, m2590v4);
                    i6 = length + m2590v4;
                    c2360t.m2568D(m2590v4);
                }
            }
            return new C2378j(i3 == 0 ? null : Collections.singletonList(bArr), m2585q + 1);
        } catch (ArrayIndexOutOfBoundsException e2) {
            throw new C2205l0("Error parsing HEVC config", e2);
        }
    }
}
