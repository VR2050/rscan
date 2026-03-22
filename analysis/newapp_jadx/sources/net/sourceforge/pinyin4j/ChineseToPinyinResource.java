package net.sourceforge.pinyin4j;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/* loaded from: classes3.dex */
public class ChineseToPinyinResource {
    private Properties unicodeToHanyuPinyinTable;

    public static class ChineseToPinyinResourceHolder {
        public static final ChineseToPinyinResource theInstance = new ChineseToPinyinResource();

        private ChineseToPinyinResourceHolder() {
        }
    }

    public class Field {
        public static final String COMMA = ",";
        public static final String LEFT_BRACKET = "(";
        public static final String RIGHT_BRACKET = ")";

        public Field() {
        }
    }

    private String getHanyuPinyinRecordFromChar(char c2) {
        String property = getUnicodeToHanyuPinyinTable().getProperty(Integer.toHexString(c2).toUpperCase());
        if (isValidRecord(property)) {
            return property;
        }
        return null;
    }

    public static ChineseToPinyinResource getInstance() {
        return ChineseToPinyinResourceHolder.theInstance;
    }

    private Properties getUnicodeToHanyuPinyinTable() {
        return this.unicodeToHanyuPinyinTable;
    }

    private void initializeResource() {
        try {
            setUnicodeToHanyuPinyinTable(new Properties());
            getUnicodeToHanyuPinyinTable().load(ResourceHelper.getResourceInputStream("/pinyindb/unicode_to_hanyu_pinyin.txt"));
        } catch (FileNotFoundException e2) {
            e2.printStackTrace();
        } catch (IOException e3) {
            e3.printStackTrace();
        }
    }

    private boolean isValidRecord(String str) {
        return str != null && !str.equals("(none0)") && str.startsWith(Field.LEFT_BRACKET) && str.endsWith(Field.RIGHT_BRACKET);
    }

    private void setUnicodeToHanyuPinyinTable(Properties properties) {
        this.unicodeToHanyuPinyinTable = properties;
    }

    public String[] getHanyuPinyinStringArray(char c2) {
        String hanyuPinyinRecordFromChar = getHanyuPinyinRecordFromChar(c2);
        if (hanyuPinyinRecordFromChar == null) {
            return null;
        }
        return hanyuPinyinRecordFromChar.substring(hanyuPinyinRecordFromChar.indexOf(Field.LEFT_BRACKET) + 1, hanyuPinyinRecordFromChar.lastIndexOf(Field.RIGHT_BRACKET)).split(Field.COMMA);
    }

    private ChineseToPinyinResource() {
        this.unicodeToHanyuPinyinTable = null;
        initializeResource();
    }
}
