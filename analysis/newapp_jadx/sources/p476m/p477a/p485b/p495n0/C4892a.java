package p476m.p477a.p485b.p495n0;

import java.io.Serializable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.b.n0.a */
/* loaded from: classes3.dex */
public final class C4892a implements Serializable {
    private static final long serialVersionUID = 4359112959524048036L;

    /* renamed from: c */
    public byte[] f12495c;

    /* renamed from: e */
    public int f12496e;

    public C4892a(int i2) {
        C2354n.m2462c1(i2, "Buffer capacity");
        this.f12495c = new byte[i2];
    }

    /* renamed from: a */
    public void m5556a(byte[] bArr, int i2, int i3) {
        int i4;
        if (bArr == null) {
            return;
        }
        if (i2 < 0 || i2 > bArr.length || i3 < 0 || (i4 = i2 + i3) < 0 || i4 > bArr.length) {
            StringBuilder m589K = C1499a.m589K("off: ", i2, " len: ", i3, " b.length: ");
            m589K.append(bArr.length);
            throw new IndexOutOfBoundsException(m589K.toString());
        }
        if (i3 == 0) {
            return;
        }
        int i5 = this.f12496e + i3;
        if (i5 > this.f12495c.length) {
            m5557b(i5);
        }
        System.arraycopy(bArr, i2, this.f12495c, this.f12496e, i3);
        this.f12496e = i5;
    }

    /* renamed from: b */
    public final void m5557b(int i2) {
        byte[] bArr = new byte[Math.max(this.f12495c.length << 1, i2)];
        System.arraycopy(this.f12495c, 0, bArr, 0, this.f12496e);
        this.f12495c = bArr;
    }
}
