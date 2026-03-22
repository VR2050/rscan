package com.alibaba.fastjson;

/* loaded from: classes.dex */
public enum PropertyNamingStrategy {
    CamelCase,
    PascalCase,
    SnakeCase,
    KebabCase,
    NoChange;

    /* renamed from: com.alibaba.fastjson.PropertyNamingStrategy$1 */
    public static /* synthetic */ class C31231 {
        public static final /* synthetic */ int[] $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy;

        static {
            PropertyNamingStrategy.values();
            int[] iArr = new int[5];
            $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy = iArr;
            try {
                iArr[PropertyNamingStrategy.SnakeCase.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy[PropertyNamingStrategy.KebabCase.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy[PropertyNamingStrategy.PascalCase.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy[PropertyNamingStrategy.CamelCase.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$PropertyNamingStrategy[PropertyNamingStrategy.NoChange.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
        }
    }

    public String translate(String str) {
        int ordinal = ordinal();
        int i2 = 0;
        if (ordinal == 0) {
            char charAt = str.charAt(0);
            if (charAt < 'A' || charAt > 'Z') {
                return str;
            }
            char[] charArray = str.toCharArray();
            charArray[0] = (char) (charArray[0] + ' ');
            return new String(charArray);
        }
        if (ordinal == 1) {
            char charAt2 = str.charAt(0);
            if (charAt2 < 'a' || charAt2 > 'z') {
                return str;
            }
            char[] charArray2 = str.toCharArray();
            charArray2[0] = (char) (charArray2[0] - ' ');
            return new String(charArray2);
        }
        if (ordinal == 2) {
            StringBuilder sb = new StringBuilder();
            while (i2 < str.length()) {
                char charAt3 = str.charAt(i2);
                if (charAt3 < 'A' || charAt3 > 'Z') {
                    sb.append(charAt3);
                } else {
                    char c2 = (char) (charAt3 + ' ');
                    if (i2 > 0) {
                        sb.append('_');
                    }
                    sb.append(c2);
                }
                i2++;
            }
            return sb.toString();
        }
        if (ordinal != 3) {
            return str;
        }
        StringBuilder sb2 = new StringBuilder();
        while (i2 < str.length()) {
            char charAt4 = str.charAt(i2);
            if (charAt4 < 'A' || charAt4 > 'Z') {
                sb2.append(charAt4);
            } else {
                char c3 = (char) (charAt4 + ' ');
                if (i2 > 0) {
                    sb2.append('-');
                }
                sb2.append(c3);
            }
            i2++;
        }
        return sb2.toString();
    }
}
