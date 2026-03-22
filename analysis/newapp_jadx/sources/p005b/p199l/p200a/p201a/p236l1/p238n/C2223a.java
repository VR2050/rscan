package p005b.p199l.p200a.p201a.p236l1.p238n;

import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;

/* renamed from: b.l.a.a.l1.n.a */
/* loaded from: classes.dex */
public final class C2223a extends AbstractC2208c {

    /* renamed from: n */
    public final C2224b f5398n;

    public C2223a(List<byte[]> list) {
        super("DvbDecoder");
        byte[] bArr = list.get(0);
        int length = bArr.length;
        int i2 = 0 + 1;
        int i3 = i2 + 1;
        int i4 = ((bArr[0] & 255) << 8) | (bArr[i2] & 255);
        int i5 = i3 + 1;
        this.f5398n = new C2224b(i4, (bArr[i5] & 255) | ((bArr[i3] & 255) << 8));
    }

    /*  JADX ERROR: JadxRuntimeException in pass: ModVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't remove SSA var: r2v0 b.l.a.a.l1.n.c, still in use, count: 2, list:
          (r2v0 b.l.a.a.l1.n.c) from 0x0298: PHI (r2v1 b.l.a.a.l1.n.c) = (r2v0 b.l.a.a.l1.n.c), (r2v4 b.l.a.a.l1.n.c) binds: [B:102:0x0290, B:141:0x03cf] A[DONT_GENERATE, DONT_INLINE]
          (r2v0 b.l.a.a.l1.n.c) from 0x0257: MOVE (r26v6 b.l.a.a.l1.n.c) = (r2v0 b.l.a.a.l1.n.c)
        	at jadx.core.utils.InsnRemover.removeSsaVar(InsnRemover.java:162)
        	at jadx.core.utils.InsnRemover.unbindResult(InsnRemover.java:127)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:91)
        	at jadx.core.utils.InsnRemover.addAndUnbind(InsnRemover.java:57)
        	at jadx.core.dex.visitors.ModVisitor.removeStep(ModVisitor.java:447)
        	at jadx.core.dex.visitors.ModVisitor.visit(ModVisitor.java:96)
        */
    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e mo2047j(byte[] r35, int r36, boolean r37) {
        /*
            Method dump skipped, instructions count: 1072
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p238n.C2223a.mo2047j(byte[], int, boolean):b.l.a.a.l1.e");
    }
}
