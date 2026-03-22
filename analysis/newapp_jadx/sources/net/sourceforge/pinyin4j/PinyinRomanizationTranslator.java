package net.sourceforge.pinyin4j;

import p005b.p295o.p296a.p297a.C2676d;
import p005b.p295o.p296a.p297a.C2682j;

/* loaded from: classes3.dex */
public class PinyinRomanizationTranslator {
    public static String convertRomanizationSystem(String str, PinyinRomanizationType pinyinRomanizationType, PinyinRomanizationType pinyinRomanizationType2) {
        String extractPinyinString = TextHelper.extractPinyinString(str);
        String extractToneNumber = TextHelper.extractToneNumber(str);
        try {
            C2676d m3174g = PinyinRomanizationResource.getInstance().getPinyinMappingDoc().m3174g("//" + pinyinRomanizationType.getTagName() + "[text()='" + extractPinyinString + "']");
            if (m3174g == null) {
                return null;
            }
            return m3174g.m3182l("../" + pinyinRomanizationType2.getTagName() + "/text()") + extractToneNumber;
        } catch (C2682j e2) {
            e2.printStackTrace();
            return null;
        }
    }
}
