package p005b.p199l.p200a.p201a.p251q1;

import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.p250p1.C2347g;
import p005b.p199l.p200a.p201a.p250p1.C2358r;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.q1.h */
/* loaded from: classes.dex */
public final class C2376h {

    /* renamed from: a */
    public final List<byte[]> f6178a;

    /* renamed from: b */
    public final int f6179b;

    /* renamed from: c */
    public final int f6180c;

    /* renamed from: d */
    public final int f6181d;

    /* renamed from: e */
    public final float f6182e;

    public C2376h(List<byte[]> list, int i2, int i3, int i4, float f2) {
        this.f6178a = list;
        this.f6179b = i2;
        this.f6180c = i3;
        this.f6181d = i4;
        this.f6182e = f2;
    }

    /* renamed from: a */
    public static byte[] m2613a(C2360t c2360t) {
        int m2590v = c2360t.m2590v();
        int i2 = c2360t.f6134b;
        c2360t.m2568D(m2590v);
        byte[] bArr = c2360t.f6133a;
        byte[] bArr2 = C2347g.f6054a;
        byte[] bArr3 = new byte[bArr2.length + m2590v];
        System.arraycopy(bArr2, 0, bArr3, 0, bArr2.length);
        System.arraycopy(bArr, i2, bArr3, bArr2.length, m2590v);
        return bArr3;
    }

    /* renamed from: b */
    public static C2376h m2614b(C2360t c2360t) {
        int i2;
        int i3;
        float f2;
        try {
            c2360t.m2568D(4);
            int m2585q = (c2360t.m2585q() & 3) + 1;
            if (m2585q == 3) {
                throw new IllegalStateException();
            }
            ArrayList arrayList = new ArrayList();
            int m2585q2 = c2360t.m2585q() & 31;
            for (int i4 = 0; i4 < m2585q2; i4++) {
                arrayList.add(m2613a(c2360t));
            }
            int m2585q3 = c2360t.m2585q();
            for (int i5 = 0; i5 < m2585q3; i5++) {
                arrayList.add(m2613a(c2360t));
            }
            if (m2585q2 > 0) {
                C2358r.b m2551d = C2358r.m2551d((byte[]) arrayList.get(0), m2585q, ((byte[]) arrayList.get(0)).length);
                int i6 = m2551d.f6120e;
                int i7 = m2551d.f6121f;
                f2 = m2551d.f6122g;
                i2 = i6;
                i3 = i7;
            } else {
                i2 = -1;
                i3 = -1;
                f2 = 1.0f;
            }
            return new C2376h(arrayList, m2585q, i2, i3, f2);
        } catch (ArrayIndexOutOfBoundsException e2) {
            throw new C2205l0("Error parsing AVC config", e2);
        }
    }
}
