package p005b.p199l.p266d.p267a0.p270e;

import java.lang.reflect.Array;

/* renamed from: b.l.d.a0.e.b */
/* loaded from: classes2.dex */
public final class C2517b {

    /* renamed from: a */
    public final byte[][] f6799a;

    /* renamed from: b */
    public final int f6800b;

    /* renamed from: c */
    public final int f6801c;

    public C2517b(int i2, int i3) {
        this.f6799a = (byte[][]) Array.newInstance((Class<?>) byte.class, i3, i2);
        this.f6800b = i2;
        this.f6801c = i3;
    }

    /* renamed from: a */
    public byte m2907a(int i2, int i3) {
        return this.f6799a[i3][i2];
    }

    /* renamed from: b */
    public void m2908b(int i2, int i3, int i4) {
        this.f6799a[i3][i2] = (byte) i4;
    }

    /* renamed from: c */
    public void m2909c(int i2, int i3, boolean z) {
        this.f6799a[i3][i2] = z ? (byte) 1 : (byte) 0;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder((this.f6800b * 2 * this.f6801c) + 2);
        for (int i2 = 0; i2 < this.f6801c; i2++) {
            byte[] bArr = this.f6799a[i2];
            for (int i3 = 0; i3 < this.f6800b; i3++) {
                byte b2 = bArr[i3];
                if (b2 == 0) {
                    sb.append(" 0");
                } else if (b2 != 1) {
                    sb.append("  ");
                } else {
                    sb.append(" 1");
                }
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
