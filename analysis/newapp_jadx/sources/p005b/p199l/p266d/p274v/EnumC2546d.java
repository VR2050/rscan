package p005b.p199l.p266d.p274v;

import java.util.HashMap;
import java.util.Map;
import p005b.p199l.p266d.C2525g;

/* renamed from: b.l.d.v.d */
/* loaded from: classes2.dex */
public enum EnumC2546d {
    Cp437(new int[]{0, 2}, new String[0]),
    ISO8859_1(new int[]{1, 3}, "ISO-8859-1"),
    ISO8859_2(4, "ISO-8859-2"),
    ISO8859_3(5, "ISO-8859-3"),
    ISO8859_4(6, "ISO-8859-4"),
    ISO8859_5(7, "ISO-8859-5"),
    ISO8859_6(8, "ISO-8859-6"),
    ISO8859_7(9, "ISO-8859-7"),
    ISO8859_8(10, "ISO-8859-8"),
    ISO8859_9(11, "ISO-8859-9"),
    ISO8859_10(12, "ISO-8859-10"),
    ISO8859_11(13, "ISO-8859-11"),
    ISO8859_13(15, "ISO-8859-13"),
    ISO8859_14(16, "ISO-8859-14"),
    ISO8859_15(17, "ISO-8859-15"),
    ISO8859_16(18, "ISO-8859-16"),
    SJIS(20, "Shift_JIS"),
    Cp1250(21, "windows-1250"),
    Cp1251(22, "windows-1251"),
    Cp1252(23, "windows-1252"),
    Cp1256(24, "windows-1256"),
    UnicodeBigUnmarked(25, "UTF-16BE", "UnicodeBig"),
    UTF8(26, "UTF-8"),
    ASCII(new int[]{27, 170}, "US-ASCII"),
    Big5(28),
    GB18030(29, "GB2312", "EUC_CN", "GBK"),
    EUC_KR(30, "EUC-KR");


    /* renamed from: E */
    public static final Map<Integer, EnumC2546d> f6904E = new HashMap();

    /* renamed from: F */
    public static final Map<String, EnumC2546d> f6905F = new HashMap();

    /* renamed from: H */
    public final int[] f6930H;

    /* renamed from: I */
    public final String[] f6931I;

    static {
        EnumC2546d[] values = values();
        for (int i2 = 0; i2 < 27; i2++) {
            EnumC2546d enumC2546d = values[i2];
            for (int i3 : enumC2546d.f6930H) {
                f6904E.put(Integer.valueOf(i3), enumC2546d);
            }
            f6905F.put(enumC2546d.name(), enumC2546d);
            for (String str : enumC2546d.f6931I) {
                f6905F.put(str, enumC2546d);
            }
        }
    }

    EnumC2546d(int i2, String... strArr) {
        this.f6930H = new int[]{i2};
        this.f6931I = strArr;
    }

    /* renamed from: a */
    public static EnumC2546d m2966a(int i2) {
        if (i2 < 0 || i2 >= 900) {
            throw C2525g.m2925a();
        }
        return f6904E.get(Integer.valueOf(i2));
    }

    EnumC2546d(int i2) {
        this.f6930H = new int[]{i2};
        this.f6931I = new String[0];
    }

    EnumC2546d(int[] iArr, String... strArr) {
        this.f6930H = iArr;
        this.f6931I = strArr;
    }
}
