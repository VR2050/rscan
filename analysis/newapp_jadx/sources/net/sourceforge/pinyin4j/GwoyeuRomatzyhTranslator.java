package net.sourceforge.pinyin4j;

import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2682j;

/* loaded from: classes3.dex */
public class GwoyeuRomatzyhTranslator {
    private static String[] tones = {"_I", "_II", "_III", "_IV", "_V"};

    public static String convertHanyuPinyinToGwoyeuRomatzyh(String str) {
        String extractPinyinString = TextHelper.extractPinyinString(str);
        String extractToneNumber = TextHelper.extractToneNumber(str);
        try {
            C2676d m3174g = GwoyeuRomatzyhResource.getInstance().getPinyinToGwoyeuMappingDoc().m3174g("//" + PinyinRomanizationType.HANYU_PINYIN.getTagName() + "[text()='" + extractPinyinString + "']");
            if (m3174g == null) {
                return null;
            }
            return m3174g.m3182l("../" + PinyinRomanizationType.GWOYEU_ROMATZYH.getTagName() + tones[Integer.parseInt(extractToneNumber) - 1] + "/text()");
        } catch (C2682j e2) {
            e2.printStackTrace();
            return null;
        }
    }
}
