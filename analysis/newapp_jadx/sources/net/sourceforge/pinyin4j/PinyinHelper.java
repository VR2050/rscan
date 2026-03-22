package net.sourceforge.pinyin4j;

import net.sourceforge.pinyin4j.format.HanyuPinyinOutputFormat;

/* loaded from: classes3.dex */
public class PinyinHelper {
    private PinyinHelper() {
    }

    private static String[] convertToGwoyeuRomatzyhStringArray(char c2) {
        String[] unformattedHanyuPinyinStringArray = getUnformattedHanyuPinyinStringArray(c2);
        if (unformattedHanyuPinyinStringArray == null) {
            return null;
        }
        String[] strArr = new String[unformattedHanyuPinyinStringArray.length];
        for (int i2 = 0; i2 < unformattedHanyuPinyinStringArray.length; i2++) {
            strArr[i2] = GwoyeuRomatzyhTranslator.convertHanyuPinyinToGwoyeuRomatzyh(unformattedHanyuPinyinStringArray[i2]);
        }
        return strArr;
    }

    private static String[] convertToTargetPinyinStringArray(char c2, PinyinRomanizationType pinyinRomanizationType) {
        String[] unformattedHanyuPinyinStringArray = getUnformattedHanyuPinyinStringArray(c2);
        if (unformattedHanyuPinyinStringArray == null) {
            return null;
        }
        String[] strArr = new String[unformattedHanyuPinyinStringArray.length];
        for (int i2 = 0; i2 < unformattedHanyuPinyinStringArray.length; i2++) {
            strArr[i2] = PinyinRomanizationTranslator.convertRomanizationSystem(unformattedHanyuPinyinStringArray[i2], PinyinRomanizationType.HANYU_PINYIN, pinyinRomanizationType);
        }
        return strArr;
    }

    private static String getFirstHanyuPinyinString(char c2, HanyuPinyinOutputFormat hanyuPinyinOutputFormat) {
        String[] formattedHanyuPinyinStringArray = getFormattedHanyuPinyinStringArray(c2, hanyuPinyinOutputFormat);
        if (formattedHanyuPinyinStringArray == null || formattedHanyuPinyinStringArray.length <= 0) {
            return null;
        }
        return formattedHanyuPinyinStringArray[0];
    }

    private static String[] getFormattedHanyuPinyinStringArray(char c2, HanyuPinyinOutputFormat hanyuPinyinOutputFormat) {
        String[] unformattedHanyuPinyinStringArray = getUnformattedHanyuPinyinStringArray(c2);
        if (unformattedHanyuPinyinStringArray == null) {
            return null;
        }
        for (int i2 = 0; i2 < unformattedHanyuPinyinStringArray.length; i2++) {
            unformattedHanyuPinyinStringArray[i2] = PinyinFormatter.formatHanyuPinyin(unformattedHanyuPinyinStringArray[i2], hanyuPinyinOutputFormat);
        }
        return unformattedHanyuPinyinStringArray;
    }

    private static String[] getUnformattedHanyuPinyinStringArray(char c2) {
        return ChineseToPinyinResource.getInstance().getHanyuPinyinStringArray(c2);
    }

    public static String[] toGwoyeuRomatzyhStringArray(char c2) {
        return convertToGwoyeuRomatzyhStringArray(c2);
    }

    public static String toHanyuPinyinString(String str, HanyuPinyinOutputFormat hanyuPinyinOutputFormat, String str2) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i2 = 0; i2 < str.length(); i2++) {
            String firstHanyuPinyinString = getFirstHanyuPinyinString(str.charAt(i2), hanyuPinyinOutputFormat);
            if (firstHanyuPinyinString != null) {
                stringBuffer.append(firstHanyuPinyinString);
                if (i2 != str.length() - 1) {
                    stringBuffer.append(str2);
                }
            } else {
                stringBuffer.append(str.charAt(i2));
            }
        }
        return stringBuffer.toString();
    }

    public static String[] toHanyuPinyinStringArray(char c2) {
        return getUnformattedHanyuPinyinStringArray(c2);
    }

    public static String[] toMPS2PinyinStringArray(char c2) {
        return convertToTargetPinyinStringArray(c2, PinyinRomanizationType.MPS2_PINYIN);
    }

    public static String[] toTongyongPinyinStringArray(char c2) {
        return convertToTargetPinyinStringArray(c2, PinyinRomanizationType.TONGYONG_PINYIN);
    }

    public static String[] toWadeGilesPinyinStringArray(char c2) {
        return convertToTargetPinyinStringArray(c2, PinyinRomanizationType.WADEGILES_PINYIN);
    }

    public static String[] toYalePinyinStringArray(char c2) {
        return convertToTargetPinyinStringArray(c2, PinyinRomanizationType.YALE_PINYIN);
    }

    public static String[] toHanyuPinyinStringArray(char c2, HanyuPinyinOutputFormat hanyuPinyinOutputFormat) {
        return getFormattedHanyuPinyinStringArray(c2, hanyuPinyinOutputFormat);
    }
}
