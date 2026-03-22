package com.alibaba.fastjson.parser.deserializer;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONPObject;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.JSONLexerBase;
import java.lang.reflect.Type;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class JSONPDeserializer implements ObjectDeserializer {
    public static final JSONPDeserializer instance = new JSONPDeserializer();

    /* JADX WARN: Type inference failed for: r1v1, types: [T, com.alibaba.fastjson.JSONPObject] */
    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public <T> T deserialze(DefaultJSONParser defaultJSONParser, Type type, Object obj) {
        int i2;
        JSONLexerBase jSONLexerBase = (JSONLexerBase) defaultJSONParser.getLexer();
        String scanSymbolUnQuoted = jSONLexerBase.scanSymbolUnQuoted(defaultJSONParser.getSymbolTable());
        jSONLexerBase.nextToken();
        int i3 = jSONLexerBase.token();
        if (i3 == 25) {
            String scanSymbolUnQuoted2 = jSONLexerBase.scanSymbolUnQuoted(defaultJSONParser.getSymbolTable());
            scanSymbolUnQuoted = C1499a.m637w(scanSymbolUnQuoted, ".") + scanSymbolUnQuoted2;
            jSONLexerBase.nextToken();
            i3 = jSONLexerBase.token();
        }
        ?? r1 = (T) new JSONPObject(scanSymbolUnQuoted);
        if (i3 != 10) {
            StringBuilder m586H = C1499a.m586H("illegal jsonp : ");
            m586H.append(jSONLexerBase.info());
            throw new JSONException(m586H.toString());
        }
        jSONLexerBase.nextToken();
        while (true) {
            r1.addParameter(defaultJSONParser.parse());
            i2 = jSONLexerBase.token();
            if (i2 != 16) {
                break;
            }
            jSONLexerBase.nextToken();
        }
        if (i2 != 11) {
            StringBuilder m586H2 = C1499a.m586H("illegal jsonp : ");
            m586H2.append(jSONLexerBase.info());
            throw new JSONException(m586H2.toString());
        }
        jSONLexerBase.nextToken();
        if (jSONLexerBase.token() == 24) {
            jSONLexerBase.nextToken();
        }
        return r1;
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public int getFastMatchToken() {
        return 0;
    }
}
