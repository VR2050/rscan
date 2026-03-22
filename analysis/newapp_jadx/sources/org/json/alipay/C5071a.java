package org.json.alipay;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;

/* renamed from: org.json.alipay.a */
/* loaded from: classes3.dex */
public class C5071a {

    /* renamed from: a */
    private ArrayList f12993a;

    public C5071a() {
        this.f12993a = new ArrayList();
    }

    public C5071a(Object obj) {
        this();
        if (!obj.getClass().isArray()) {
            throw new JSONException("JSONArray initial value should be a string or collection or array.");
        }
        int length = Array.getLength(obj);
        for (int i2 = 0; i2 < length; i2++) {
            this.f12993a.add(Array.get(obj, i2));
        }
    }

    public C5071a(String str) {
        this(new C5073c(str));
    }

    public C5071a(Collection collection) {
        this.f12993a = collection == null ? new ArrayList() : new ArrayList(collection);
    }

    public C5071a(C5073c c5073c) {
        this();
        char c2;
        ArrayList arrayList;
        Object m5713d;
        char m5712c = c5073c.m5712c();
        if (m5712c == '[') {
            c2 = ']';
        } else {
            if (m5712c != '(') {
                throw c5073c.m5709a("A JSONArray text must start with '['");
            }
            c2 = ')';
        }
        if (c5073c.m5712c() == ']') {
            return;
        }
        do {
            c5073c.m5710a();
            char m5712c2 = c5073c.m5712c();
            c5073c.m5710a();
            if (m5712c2 == ',') {
                arrayList = this.f12993a;
                m5713d = null;
            } else {
                arrayList = this.f12993a;
                m5713d = c5073c.m5713d();
            }
            arrayList.add(m5713d);
            char m5712c3 = c5073c.m5712c();
            if (m5712c3 != ')') {
                if (m5712c3 != ',' && m5712c3 != ';') {
                    if (m5712c3 != ']') {
                        throw c5073c.m5709a("Expected a ',' or ']'");
                    }
                }
            }
            if (c2 == m5712c3) {
                return;
            }
            throw c5073c.m5709a("Expected a '" + new Character(c2) + "'");
        } while (c5073c.m5712c() != ']');
    }

    /* renamed from: a */
    private String m5699a(String str) {
        int size = this.f12993a.size();
        StringBuffer stringBuffer = new StringBuffer();
        for (int i2 = 0; i2 < size; i2++) {
            if (i2 > 0) {
                stringBuffer.append(str);
            }
            stringBuffer.append(C5072b.m5702a(this.f12993a.get(i2)));
        }
        return stringBuffer.toString();
    }

    /* renamed from: a */
    public final int m5700a() {
        return this.f12993a.size();
    }

    /* renamed from: a */
    public final Object m5701a(int i2) {
        Object obj = (i2 < 0 || i2 >= this.f12993a.size()) ? null : this.f12993a.get(i2);
        if (obj != null) {
            return obj;
        }
        throw new JSONException("JSONArray[" + i2 + "] not found.");
    }

    public String toString() {
        try {
            return "[" + m5699a(ChineseToPinyinResource.Field.COMMA) + ']';
        } catch (Exception unused) {
            return null;
        }
    }
}
