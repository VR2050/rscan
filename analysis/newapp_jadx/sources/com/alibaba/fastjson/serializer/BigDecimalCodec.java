package com.alibaba.fastjson.serializer;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.JSONLexer;
import com.alibaba.fastjson.parser.deserializer.ObjectDeserializer;
import com.alibaba.fastjson.util.TypeUtils;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class BigDecimalCodec implements ObjectSerializer, ObjectDeserializer {
    public static final BigDecimal LOW = BigDecimal.valueOf(-9007199254740991L);
    public static final BigDecimal HIGH = BigDecimal.valueOf(9007199254740991L);
    public static final BigDecimalCodec instance = new BigDecimalCodec();

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public <T> T deserialze(DefaultJSONParser defaultJSONParser, Type type, Object obj) {
        try {
            return (T) deserialze(defaultJSONParser);
        } catch (Exception e2) {
            throw new JSONException(C1499a.m636v("parseDecimal error, field : ", obj), e2);
        }
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public int getFastMatchToken() {
        return 2;
    }

    @Override // com.alibaba.fastjson.serializer.ObjectSerializer
    public void write(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        SerializeWriter serializeWriter = jSONSerializer.out;
        if (obj == null) {
            serializeWriter.writeNull(SerializerFeature.WriteNullNumberAsZero);
            return;
        }
        BigDecimal bigDecimal = (BigDecimal) obj;
        int scale = bigDecimal.scale();
        String bigDecimal2 = (!SerializerFeature.isEnabled(i2, serializeWriter.features, SerializerFeature.WriteBigDecimalAsPlain) || scale < -100 || scale >= 100) ? bigDecimal.toString() : bigDecimal.toPlainString();
        if (scale == 0 && bigDecimal2.length() >= 16 && SerializerFeature.isEnabled(i2, serializeWriter.features, SerializerFeature.BrowserCompatible) && (bigDecimal.compareTo(LOW) < 0 || bigDecimal.compareTo(HIGH) > 0)) {
            serializeWriter.writeString(bigDecimal2);
            return;
        }
        serializeWriter.write(bigDecimal2);
        if (serializeWriter.isEnabled(SerializerFeature.WriteClassName) && type != BigDecimal.class && bigDecimal.scale() == 0) {
            serializeWriter.write(46);
        }
    }

    public static <T> T deserialze(DefaultJSONParser defaultJSONParser) {
        JSONLexer jSONLexer = defaultJSONParser.lexer;
        if (jSONLexer.token() == 2) {
            T t = (T) jSONLexer.decimalValue();
            jSONLexer.nextToken(16);
            return t;
        }
        if (jSONLexer.token() == 3) {
            T t2 = (T) jSONLexer.decimalValue();
            jSONLexer.nextToken(16);
            return t2;
        }
        Object parse = defaultJSONParser.parse();
        if (parse == null) {
            return null;
        }
        return (T) TypeUtils.castToBigDecimal(parse);
    }
}
