package p005b.p199l.p266d.p267a0.p268c;

/* renamed from: b.l.d.a0.c.h */
/* loaded from: classes2.dex */
public enum EnumC2507h {
    TERMINATOR(new int[]{0, 0, 0}, 0),
    NUMERIC(new int[]{10, 12, 14}, 1),
    ALPHANUMERIC(new int[]{9, 11, 13}, 2),
    STRUCTURED_APPEND(new int[]{0, 0, 0}, 3),
    BYTE(new int[]{8, 16, 16}, 4),
    ECI(new int[]{0, 0, 0}, 7),
    KANJI(new int[]{8, 10, 12}, 8),
    FNC1_FIRST_POSITION(new int[]{0, 0, 0}, 5),
    FNC1_SECOND_POSITION(new int[]{0, 0, 0}, 9),
    HANZI(new int[]{8, 10, 12}, 13);


    /* renamed from: o */
    public final int[] f6761o;

    /* renamed from: p */
    public final int f6762p;

    EnumC2507h(int[] iArr, int i2) {
        this.f6761o = iArr;
        this.f6762p = i2;
    }

    /* renamed from: a */
    public int m2886a(C2509j c2509j) {
        int i2 = c2509j.f6766c;
        return this.f6761o[i2 <= 9 ? (char) 0 : i2 <= 26 ? (char) 1 : (char) 2];
    }
}
