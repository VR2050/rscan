package net.sourceforge.pinyin4j;

/* loaded from: classes3.dex */
public class PinyinRomanizationType {
    public String tagName;
    public static final PinyinRomanizationType HANYU_PINYIN = new PinyinRomanizationType("Hanyu");
    public static final PinyinRomanizationType WADEGILES_PINYIN = new PinyinRomanizationType("Wade");
    public static final PinyinRomanizationType MPS2_PINYIN = new PinyinRomanizationType("MPSII");
    public static final PinyinRomanizationType YALE_PINYIN = new PinyinRomanizationType("Yale");
    public static final PinyinRomanizationType TONGYONG_PINYIN = new PinyinRomanizationType("Tongyong");
    public static final PinyinRomanizationType GWOYEU_ROMATZYH = new PinyinRomanizationType("Gwoyeu");

    public PinyinRomanizationType(String str) {
        setTagName(str);
    }

    public String getTagName() {
        return this.tagName;
    }

    public void setTagName(String str) {
        this.tagName = str;
    }
}
