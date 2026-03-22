package p005b.p199l.p266d.p280x.p281b;

import p005b.p199l.p266d.C2522d;
import p005b.p199l.p266d.p274v.p276m.C2555a;
import p005b.p199l.p266d.p274v.p276m.C2557c;
import p005b.p199l.p266d.p274v.p276m.C2559e;

/* renamed from: b.l.d.x.b.c */
/* loaded from: classes2.dex */
public final class C2570c {

    /* renamed from: a */
    public final C2557c f7016a = new C2557c(C2555a.f6972h);

    /* renamed from: a */
    public final void m2998a(byte[] bArr, int i2, int i3, int i4, int i5) {
        int i6 = i3 + i4;
        int i7 = i5 == 0 ? 1 : 2;
        int[] iArr = new int[i6 / i7];
        for (int i8 = 0; i8 < i6; i8++) {
            if (i5 == 0 || i8 % 2 == i5 - 1) {
                iArr[i8 / i7] = bArr[i8 + i2] & 255;
            }
        }
        try {
            this.f7016a.m2986a(iArr, i4 / i7);
            for (int i9 = 0; i9 < i3; i9++) {
                if (i5 == 0 || i9 % 2 == i5 - 1) {
                    bArr[i9 + i2] = (byte) iArr[i9 / i7];
                }
            }
        } catch (C2559e unused) {
            throw C2522d.m2924a();
        }
    }
}
