package p005b.p199l.p200a.p201a.p202a1;

import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;

/* renamed from: b.l.a.a.a1.x */
/* loaded from: classes.dex */
public final class C1932x extends AbstractC1926r {
    @Override // p005b.p199l.p200a.p201a.p202a1.AbstractC1926r
    /* renamed from: a */
    public InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar) {
        int i2 = aVar.f3080d;
        if (i2 == 3 || i2 == 2 || i2 == 268435456 || i2 == 536870912 || i2 == 805306368) {
            return i2 != 2 ? new InterfaceC1920l.a(aVar.f3078b, aVar.f3079c, 2) : InterfaceC1920l.a.f3077a;
        }
        throw new InterfaceC1920l.b(aVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0083 A[ADDED_TO_REGION, LOOP:3: B:29:0x0083->B:30:0x0085, LOOP_START, PHI: r0
      0x0083: PHI (r0v1 int) = (r0v0 int), (r0v2 int) binds: [B:12:0x0032, B:30:0x0085] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1256e(java.nio.ByteBuffer r9) {
        /*
            r8 = this;
            int r0 = r9.position()
            int r1 = r9.limit()
            int r2 = r1 - r0
            b.l.a.a.a1.l$a r3 = r8.f3122b
            int r3 = r3.f3080d
            r4 = 805306368(0x30000000, float:4.656613E-10)
            r5 = 536870912(0x20000000, float:1.0842022E-19)
            r6 = 268435456(0x10000000, float:2.524355E-29)
            r7 = 3
            if (r3 == r7) goto L28
            if (r3 == r6) goto L2a
            if (r3 == r5) goto L26
            if (r3 != r4) goto L20
            int r2 = r2 / 2
            goto L2a
        L20:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            r9.<init>()
            throw r9
        L26:
            int r2 = r2 / 3
        L28:
            int r2 = r2 * 2
        L2a:
            java.nio.ByteBuffer r2 = r8.m1278k(r2)
            b.l.a.a.a1.l$a r3 = r8.f3122b
            int r3 = r3.f3080d
            if (r3 == r7) goto L83
            if (r3 == r6) goto L6e
            if (r3 == r5) goto L57
            if (r3 != r4) goto L51
        L3a:
            if (r0 >= r1) goto L98
            int r3 = r0 + 2
            byte r3 = r9.get(r3)
            r2.put(r3)
            int r3 = r0 + 3
            byte r3 = r9.get(r3)
            r2.put(r3)
            int r0 = r0 + 4
            goto L3a
        L51:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            r9.<init>()
            throw r9
        L57:
            if (r0 >= r1) goto L98
            int r3 = r0 + 1
            byte r3 = r9.get(r3)
            r2.put(r3)
            int r3 = r0 + 2
            byte r3 = r9.get(r3)
            r2.put(r3)
            int r0 = r0 + 3
            goto L57
        L6e:
            if (r0 >= r1) goto L98
            int r3 = r0 + 1
            byte r3 = r9.get(r3)
            r2.put(r3)
            byte r3 = r9.get(r0)
            r2.put(r3)
            int r0 = r0 + 2
            goto L6e
        L83:
            if (r0 >= r1) goto L98
            r3 = 0
            r2.put(r3)
            byte r3 = r9.get(r0)
            r3 = r3 & 255(0xff, float:3.57E-43)
            int r3 = r3 + (-128)
            byte r3 = (byte) r3
            r2.put(r3)
            int r0 = r0 + 1
            goto L83
        L98:
            int r0 = r9.limit()
            r9.position(r0)
            r2.flip()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.C1932x.mo1256e(java.nio.ByteBuffer):void");
    }
}
