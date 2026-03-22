package org.json.alipay;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* renamed from: org.json.alipay.b */
/* loaded from: classes3.dex */
public class C5072b {

    /* renamed from: a */
    public static final Object f12994a = new a(0);

    /* renamed from: b */
    private Map f12995b;

    /* renamed from: org.json.alipay.b$a */
    public static final class a {
        private a() {
        }

        public /* synthetic */ a(byte b2) {
            this();
        }

        public final Object clone() {
            return this;
        }

        public final boolean equals(Object obj) {
            return obj == null || obj == this;
        }

        public final String toString() {
            return "null";
        }
    }

    public C5072b() {
        this.f12995b = new HashMap();
    }

    public C5072b(String str) {
        this(new C5073c(str));
    }

    public C5072b(Map map) {
        this.f12995b = map == null ? new HashMap() : map;
    }

    public C5072b(C5073c c5073c) {
        this();
        if (c5073c.m5712c() != '{') {
            throw c5073c.m5709a("A JSONObject text must begin with '{'");
        }
        while (true) {
            char m5712c = c5073c.m5712c();
            if (m5712c == 0) {
                throw c5073c.m5709a("A JSONObject text must end with '}'");
            }
            if (m5712c == '}') {
                return;
            }
            c5073c.m5710a();
            String obj = c5073c.m5713d().toString();
            char m5712c2 = c5073c.m5712c();
            if (m5712c2 == '=') {
                if (c5073c.m5711b() != '>') {
                    c5073c.m5710a();
                }
            } else if (m5712c2 != ':') {
                throw c5073c.m5709a("Expected a ':' after a key");
            }
            Object m5713d = c5073c.m5713d();
            if (obj == null) {
                throw new JSONException("Null key.");
            }
            if (m5713d != null) {
                m5703b(m5713d);
                this.f12995b.put(obj, m5713d);
            } else {
                this.f12995b.remove(obj);
            }
            char m5712c3 = c5073c.m5712c();
            if (m5712c3 != ',' && m5712c3 != ';') {
                if (m5712c3 != '}') {
                    throw c5073c.m5709a("Expected a ',' or '}'");
                }
                return;
            } else if (c5073c.m5712c() == '}') {
                return;
            } else {
                c5073c.m5710a();
            }
        }
    }

    /* renamed from: a */
    public static String m5702a(Object obj) {
        if (obj == null || obj.equals(null)) {
            return "null";
        }
        if (!(obj instanceof Number)) {
            return ((obj instanceof Boolean) || (obj instanceof C5072b) || (obj instanceof C5071a)) ? obj.toString() : obj instanceof Map ? new C5072b((Map) obj).toString() : obj instanceof Collection ? new C5071a((Collection) obj).toString() : obj.getClass().isArray() ? new C5071a(obj).toString() : m5704c(obj.toString());
        }
        Number number = (Number) obj;
        m5703b(number);
        String obj2 = number.toString();
        if (obj2.indexOf(46) <= 0 || obj2.indexOf(101) >= 0 || obj2.indexOf(69) >= 0) {
            return obj2;
        }
        while (obj2.endsWith("0")) {
            obj2 = obj2.substring(0, obj2.length() - 1);
        }
        return obj2.endsWith(".") ? obj2.substring(0, obj2.length() - 1) : obj2;
    }

    /* renamed from: b */
    private static void m5703b(Object obj) {
        if (obj != null) {
            if (obj instanceof Double) {
                Double d2 = (Double) obj;
                if (d2.isInfinite() || d2.isNaN()) {
                    throw new JSONException("JSON does not allow non-finite numbers.");
                }
                return;
            }
            if (obj instanceof Float) {
                Float f2 = (Float) obj;
                if (f2.isInfinite() || f2.isNaN()) {
                    throw new JSONException("JSON does not allow non-finite numbers.");
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0084, code lost:
    
        if (r4 == '<') goto L35;
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:15:0x0034. Please report as an issue. */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String m5704c(java.lang.String r8) {
        /*
            if (r8 == 0) goto L9f
            int r0 = r8.length()
            if (r0 != 0) goto La
            goto L9f
        La:
            int r0 = r8.length()
            java.lang.StringBuffer r1 = new java.lang.StringBuffer
            int r2 = r0 + 4
            r1.<init>(r2)
            r2 = 34
            r1.append(r2)
            r3 = 0
            r4 = 0
        L1c:
            if (r3 >= r0) goto L97
            char r5 = r8.charAt(r3)
            r6 = 12
            if (r5 == r6) goto L90
            r6 = 13
            if (r5 == r6) goto L8d
            r6 = 92
            if (r5 == r2) goto L86
            r7 = 47
            if (r5 == r7) goto L82
            if (r5 == r6) goto L86
            switch(r5) {
                case 8: goto L7c;
                case 9: goto L79;
                case 10: goto L76;
                default: goto L37;
            }
        L37:
            r4 = 32
            if (r5 < r4) goto L4b
            r4 = 128(0x80, float:1.8E-43)
            if (r5 < r4) goto L43
            r4 = 160(0xa0, float:2.24E-43)
            if (r5 < r4) goto L4b
        L43:
            r4 = 8192(0x2000, float:1.148E-41)
            if (r5 < r4) goto L89
            r4 = 8448(0x2100, float:1.1838E-41)
            if (r5 >= r4) goto L89
        L4b:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            java.lang.String r6 = "000"
            r4.<init>(r6)
            java.lang.String r6 = java.lang.Integer.toHexString(r5)
            r4.append(r6)
            java.lang.String r4 = r4.toString()
            java.lang.StringBuilder r6 = new java.lang.StringBuilder
            java.lang.String r7 = "\\u"
            r6.<init>(r7)
            int r7 = r4.length()
            int r7 = r7 + (-4)
            java.lang.String r4 = r4.substring(r7)
            r6.append(r4)
            java.lang.String r4 = r6.toString()
            goto L7e
        L76:
            java.lang.String r4 = "\\n"
            goto L7e
        L79:
            java.lang.String r4 = "\\t"
            goto L7e
        L7c:
            java.lang.String r4 = "\\b"
        L7e:
            r1.append(r4)
            goto L93
        L82:
            r7 = 60
            if (r4 != r7) goto L89
        L86:
            r1.append(r6)
        L89:
            r1.append(r5)
            goto L93
        L8d:
            java.lang.String r4 = "\\r"
            goto L7e
        L90:
            java.lang.String r4 = "\\f"
            goto L7e
        L93:
            int r3 = r3 + 1
            r4 = r5
            goto L1c
        L97:
            r1.append(r2)
            java.lang.String r8 = r1.toString()
            return r8
        L9f:
            java.lang.String r8 = "\"\""
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: org.json.alipay.C5072b.m5704c(java.lang.String):java.lang.String");
    }

    /* renamed from: a */
    public final Object m5705a(String str) {
        Object obj = str == null ? null : this.f12995b.get(str);
        if (obj != null) {
            return obj;
        }
        throw new JSONException("JSONObject[" + m5704c(str) + "] not found.");
    }

    /* renamed from: a */
    public final Iterator m5706a() {
        return this.f12995b.keySet().iterator();
    }

    /* renamed from: b */
    public final boolean m5707b(String str) {
        return this.f12995b.containsKey(str);
    }

    public String toString() {
        try {
            Iterator m5706a = m5706a();
            StringBuffer stringBuffer = new StringBuffer("{");
            while (m5706a.hasNext()) {
                if (stringBuffer.length() > 1) {
                    stringBuffer.append(',');
                }
                Object next = m5706a.next();
                stringBuffer.append(m5704c(next.toString()));
                stringBuffer.append(':');
                stringBuffer.append(m5702a(this.f12995b.get(next)));
            }
            stringBuffer.append('}');
            return stringBuffer.toString();
        } catch (Exception unused) {
            return null;
        }
    }
}
