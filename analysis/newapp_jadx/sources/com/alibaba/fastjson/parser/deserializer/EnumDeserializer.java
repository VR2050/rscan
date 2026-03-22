package com.alibaba.fastjson.parser.deserializer;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.JSONLexer;
import java.lang.reflect.Type;
import java.util.Arrays;

/* loaded from: classes.dex */
public class EnumDeserializer implements ObjectDeserializer {
    public final Class<?> enumClass;
    public long[] enumNameHashCodes;
    public final Enum[] enums;
    public final Enum[] ordinalEnums;

    /* JADX WARN: Removed duplicated region for block: B:11:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00c1 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public EnumDeserializer(java.lang.Class<?> r22) {
        /*
            Method dump skipped, instructions count: 278
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.deserializer.EnumDeserializer.<init>(java.lang.Class):void");
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public <T> T deserialze(DefaultJSONParser defaultJSONParser, Type type, Object obj) {
        try {
            JSONLexer jSONLexer = defaultJSONParser.lexer;
            int i2 = jSONLexer.token();
            if (i2 == 2) {
                int intValue = jSONLexer.intValue();
                jSONLexer.nextToken(16);
                if (intValue >= 0) {
                    Object[] objArr = this.ordinalEnums;
                    if (intValue < objArr.length) {
                        return (T) objArr[intValue];
                    }
                }
                throw new JSONException("parse enum " + this.enumClass.getName() + " error, value : " + intValue);
            }
            if (i2 != 4) {
                if (i2 == 8) {
                    jSONLexer.nextToken(16);
                    return null;
                }
                throw new JSONException("parse enum " + this.enumClass.getName() + " error, value : " + defaultJSONParser.parse());
            }
            String stringVal = jSONLexer.stringVal();
            jSONLexer.nextToken(16);
            if (stringVal.length() == 0) {
                return null;
            }
            long j2 = -3750763034362895579L;
            long j3 = -3750763034362895579L;
            for (int i3 = 0; i3 < stringVal.length(); i3++) {
                int charAt = stringVal.charAt(i3);
                long j4 = j2 ^ charAt;
                if (charAt >= 65 && charAt <= 90) {
                    charAt += 32;
                }
                j2 = j4 * 1099511628211L;
                j3 = (j3 ^ charAt) * 1099511628211L;
            }
            T t = (T) getEnumByHashCode(j2);
            if (t == null && j3 != j2) {
                t = (T) getEnumByHashCode(j3);
            }
            if (t == null && jSONLexer.isEnabled(Feature.ErrorOnEnumNotMatch)) {
                throw new JSONException("not match enum value, " + this.enumClass.getName() + " : " + stringVal);
            }
            return t;
        } catch (JSONException e2) {
            throw e2;
        } catch (Exception e3) {
            throw new JSONException(e3.getMessage(), e3);
        }
    }

    public Enum getEnumByHashCode(long j2) {
        int binarySearch;
        if (this.enums != null && (binarySearch = Arrays.binarySearch(this.enumNameHashCodes, j2)) >= 0) {
            return this.enums[binarySearch];
        }
        return null;
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public int getFastMatchToken() {
        return 2;
    }

    public Enum<?> valueOf(int i2) {
        return this.ordinalEnums[i2];
    }
}
