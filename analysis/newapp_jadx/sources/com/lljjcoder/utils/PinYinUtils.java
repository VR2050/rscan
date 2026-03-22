package com.lljjcoder.utils;

import net.sourceforge.pinyin4j.PinyinHelper;
import net.sourceforge.pinyin4j.format.HanyuPinyinOutputFormat;
import net.sourceforge.pinyin4j.format.HanyuPinyinToneType;
import net.sourceforge.pinyin4j.format.exception.BadHanyuPinyinOutputFormatCombination;

/* loaded from: classes2.dex */
public class PinYinUtils {
    private HanyuPinyinOutputFormat format;
    private String[] pinyin;

    public PinYinUtils() {
        this.format = null;
        HanyuPinyinOutputFormat hanyuPinyinOutputFormat = new HanyuPinyinOutputFormat();
        this.format = hanyuPinyinOutputFormat;
        hanyuPinyinOutputFormat.setToneType(HanyuPinyinToneType.WITHOUT_TONE);
        this.pinyin = null;
    }

    public String getCharPinYin(char c2) {
        try {
            this.pinyin = PinyinHelper.toHanyuPinyinStringArray(c2, this.format);
        } catch (BadHanyuPinyinOutputFormatCombination e2) {
            e2.printStackTrace();
        }
        String[] strArr = this.pinyin;
        if (strArr == null) {
            return null;
        }
        return strArr[0];
    }

    public String getStringPinYin(String str) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i2 = 0; i2 < str.length(); i2++) {
            String charPinYin = getCharPinYin(str.charAt(i2));
            if (charPinYin == null) {
                stringBuffer.append(str.charAt(i2));
            } else {
                stringBuffer.append(charPinYin);
            }
        }
        return stringBuffer.toString();
    }
}
