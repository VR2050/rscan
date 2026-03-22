package p005b.p199l.p266d.p267a0.p268c;

/* renamed from: b.l.d.a0.c.g */
/* loaded from: classes2.dex */
public final class C2506g {

    /* renamed from: a */
    public static final int[][] f6747a = {new int[]{21522, 0}, new int[]{20773, 1}, new int[]{24188, 2}, new int[]{23371, 3}, new int[]{17913, 4}, new int[]{16590, 5}, new int[]{20375, 6}, new int[]{19104, 7}, new int[]{30660, 8}, new int[]{29427, 9}, new int[]{32170, 10}, new int[]{30877, 11}, new int[]{26159, 12}, new int[]{25368, 13}, new int[]{27713, 14}, new int[]{26998, 15}, new int[]{5769, 16}, new int[]{5054, 17}, new int[]{7399, 18}, new int[]{6608, 19}, new int[]{1890, 20}, new int[]{597, 21}, new int[]{3340, 22}, new int[]{2107, 23}, new int[]{13663, 24}, new int[]{12392, 25}, new int[]{16177, 26}, new int[]{14854, 27}, new int[]{9396, 28}, new int[]{8579, 29}, new int[]{11994, 30}, new int[]{11245, 31}};

    /* renamed from: b */
    public final EnumC2505f f6748b;

    /* renamed from: c */
    public final byte f6749c;

    public C2506g(int i2) {
        int i3 = (i2 >> 3) & 3;
        if (i3 >= 0) {
            EnumC2505f[] enumC2505fArr = EnumC2505f.f6744h;
            if (i3 < enumC2505fArr.length) {
                this.f6748b = enumC2505fArr[i3];
                this.f6749c = (byte) (i2 & 7);
                return;
            }
        }
        throw new IllegalArgumentException();
    }

    /* renamed from: a */
    public static C2506g m2884a(int i2, int i3) {
        int m2885b;
        int i4 = Integer.MAX_VALUE;
        int i5 = 0;
        for (int[] iArr : f6747a) {
            int i6 = iArr[0];
            if (i6 == i2 || i6 == i3) {
                return new C2506g(iArr[1]);
            }
            int m2885b2 = m2885b(i2, i6);
            if (m2885b2 < i4) {
                i5 = iArr[1];
                i4 = m2885b2;
            }
            if (i2 != i3 && (m2885b = m2885b(i3, i6)) < i4) {
                i5 = iArr[1];
                i4 = m2885b;
            }
        }
        if (i4 <= 3) {
            return new C2506g(i5);
        }
        return null;
    }

    /* renamed from: b */
    public static int m2885b(int i2, int i3) {
        return Integer.bitCount(i2 ^ i3);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C2506g)) {
            return false;
        }
        C2506g c2506g = (C2506g) obj;
        return this.f6748b == c2506g.f6748b && this.f6749c == c2506g.f6749c;
    }

    public int hashCode() {
        return (this.f6748b.ordinal() << 3) | this.f6749c;
    }
}
