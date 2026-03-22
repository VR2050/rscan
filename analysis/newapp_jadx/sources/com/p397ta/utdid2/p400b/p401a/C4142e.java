package com.p397ta.utdid2.p400b.p401a;

import android.util.Xml;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: com.ta.utdid2.b.a.e */
/* loaded from: classes2.dex */
public class C4142e {
    /* renamed from: a */
    public static final void m4704a(Map map, OutputStream outputStream) {
        C4138a c4138a = new C4138a();
        c4138a.setOutput(outputStream, "utf-8");
        c4138a.startDocument(null, Boolean.TRUE);
        c4138a.setFeature(C4138a.m4666d(), true);
        m4705a(map, (String) null, (XmlSerializer) c4138a);
        c4138a.endDocument();
    }

    /* renamed from: b */
    private static Object m4709b(XmlPullParser xmlPullParser, String[] strArr) {
        int next;
        Object obj = null;
        String attributeValue = xmlPullParser.getAttributeValue(null, "name");
        String name = xmlPullParser.getName();
        if (!name.equals("null")) {
            if (name.equals("string")) {
                String str = "";
                while (true) {
                    int next2 = xmlPullParser.next();
                    if (next2 == 1) {
                        throw new XmlPullParserException("Unexpected end of document in <string>");
                    }
                    if (next2 == 3) {
                        if (xmlPullParser.getName().equals("string")) {
                            strArr[0] = attributeValue;
                            return str;
                        }
                        StringBuilder m586H = C1499a.m586H("Unexpected end tag in <string>: ");
                        m586H.append(xmlPullParser.getName());
                        throw new XmlPullParserException(m586H.toString());
                    }
                    if (next2 == 4) {
                        StringBuilder m586H2 = C1499a.m586H(str);
                        m586H2.append(xmlPullParser.getText());
                        str = m586H2.toString();
                    } else if (next2 == 2) {
                        StringBuilder m586H3 = C1499a.m586H("Unexpected start tag in <string>: ");
                        m586H3.append(xmlPullParser.getName());
                        throw new XmlPullParserException(m586H3.toString());
                    }
                }
            } else if (name.equals("int")) {
                obj = Integer.valueOf(Integer.parseInt(xmlPullParser.getAttributeValue(null, "value")));
            } else if (name.equals("long")) {
                obj = Long.valueOf(xmlPullParser.getAttributeValue(null, "value"));
            } else if (name.equals("float")) {
                obj = Float.valueOf(xmlPullParser.getAttributeValue(null, "value"));
            } else if (name.equals("double")) {
                obj = Double.valueOf(xmlPullParser.getAttributeValue(null, "value"));
            } else {
                if (!name.equals("boolean")) {
                    if (name.equals("int-array")) {
                        xmlPullParser.next();
                        int[] m4708a = m4708a(xmlPullParser, "int-array", strArr);
                        strArr[0] = attributeValue;
                        return m4708a;
                    }
                    if (name.equals("map")) {
                        xmlPullParser.next();
                        HashMap m4701a = m4701a(xmlPullParser, "map", strArr);
                        strArr[0] = attributeValue;
                        return m4701a;
                    }
                    if (!name.equals("list")) {
                        throw new XmlPullParserException(C1499a.m637w("Unknown tag: ", name));
                    }
                    xmlPullParser.next();
                    ArrayList m4699a = m4699a(xmlPullParser, "list", strArr);
                    strArr[0] = attributeValue;
                    return m4699a;
                }
                obj = Boolean.valueOf(xmlPullParser.getAttributeValue(null, "value"));
            }
        }
        do {
            next = xmlPullParser.next();
            if (next == 1) {
                throw new XmlPullParserException(C1499a.m639y("Unexpected end of document in <", name, ">"));
            }
            if (next == 3) {
                if (xmlPullParser.getName().equals(name)) {
                    strArr[0] = attributeValue;
                    return obj;
                }
                StringBuilder m591M = C1499a.m591M("Unexpected end tag in <", name, ">: ");
                m591M.append(xmlPullParser.getName());
                throw new XmlPullParserException(m591M.toString());
            }
            if (next == 4) {
                StringBuilder m591M2 = C1499a.m591M("Unexpected text in <", name, ">: ");
                m591M2.append(xmlPullParser.getName());
                throw new XmlPullParserException(m591M2.toString());
            }
        } while (next != 2);
        StringBuilder m591M3 = C1499a.m591M("Unexpected start tag in <", name, ">: ");
        m591M3.append(xmlPullParser.getName());
        throw new XmlPullParserException(m591M3.toString());
    }

    /* renamed from: a */
    public static final void m4705a(Map map, String str, XmlSerializer xmlSerializer) {
        if (map == null) {
            xmlSerializer.startTag(null, "null");
            xmlSerializer.endTag(null, "null");
            return;
        }
        xmlSerializer.startTag(null, "map");
        if (str != null) {
            xmlSerializer.attribute(null, "name", str);
        }
        for (Map.Entry entry : map.entrySet()) {
            m4702a(entry.getValue(), (String) entry.getKey(), xmlSerializer);
        }
        xmlSerializer.endTag(null, "map");
    }

    /* renamed from: a */
    public static final void m4703a(List list, String str, XmlSerializer xmlSerializer) {
        if (list == null) {
            xmlSerializer.startTag(null, "null");
            xmlSerializer.endTag(null, "null");
            return;
        }
        xmlSerializer.startTag(null, "list");
        if (str != null) {
            xmlSerializer.attribute(null, "name", str);
        }
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            m4702a(list.get(i2), (String) null, xmlSerializer);
        }
        xmlSerializer.endTag(null, "list");
    }

    /* renamed from: a */
    public static final void m4706a(byte[] bArr, String str, XmlSerializer xmlSerializer) {
        if (bArr == null) {
            xmlSerializer.startTag(null, "null");
            xmlSerializer.endTag(null, "null");
            return;
        }
        xmlSerializer.startTag(null, "byte-array");
        if (str != null) {
            xmlSerializer.attribute(null, "name", str);
        }
        xmlSerializer.attribute(null, "num", Integer.toString(bArr.length));
        StringBuilder sb = new StringBuilder(bArr.length * 2);
        for (byte b2 : bArr) {
            int i2 = b2 >> 4;
            sb.append(i2 >= 10 ? (i2 + 97) - 10 : i2 + 48);
            int i3 = b2 & 255;
            sb.append(i3 >= 10 ? (i3 + 97) - 10 : i3 + 48);
        }
        xmlSerializer.text(sb.toString());
        xmlSerializer.endTag(null, "byte-array");
    }

    /* renamed from: a */
    public static final void m4707a(int[] iArr, String str, XmlSerializer xmlSerializer) {
        if (iArr == null) {
            xmlSerializer.startTag(null, "null");
            xmlSerializer.endTag(null, "null");
            return;
        }
        xmlSerializer.startTag(null, "int-array");
        if (str != null) {
            xmlSerializer.attribute(null, "name", str);
        }
        xmlSerializer.attribute(null, "num", Integer.toString(iArr.length));
        for (int i2 : iArr) {
            xmlSerializer.startTag(null, "item");
            xmlSerializer.attribute(null, "value", Integer.toString(i2));
            xmlSerializer.endTag(null, "item");
        }
        xmlSerializer.endTag(null, "int-array");
    }

    /* renamed from: a */
    public static final void m4702a(Object obj, String str, XmlSerializer xmlSerializer) {
        String str2;
        if (obj == null) {
            xmlSerializer.startTag(null, "null");
            if (str != null) {
                xmlSerializer.attribute(null, "name", str);
            }
            xmlSerializer.endTag(null, "null");
            return;
        }
        if (obj instanceof String) {
            xmlSerializer.startTag(null, "string");
            if (str != null) {
                xmlSerializer.attribute(null, "name", str);
            }
            xmlSerializer.text(obj.toString());
            xmlSerializer.endTag(null, "string");
            return;
        }
        if (obj instanceof Integer) {
            str2 = "int";
        } else if (obj instanceof Long) {
            str2 = "long";
        } else if (obj instanceof Float) {
            str2 = "float";
        } else if (obj instanceof Double) {
            str2 = "double";
        } else {
            if (!(obj instanceof Boolean)) {
                if (obj instanceof byte[]) {
                    m4706a((byte[]) obj, str, xmlSerializer);
                    return;
                }
                if (obj instanceof int[]) {
                    m4707a((int[]) obj, str, xmlSerializer);
                    return;
                }
                if (obj instanceof Map) {
                    m4705a((Map) obj, str, xmlSerializer);
                    return;
                }
                if (obj instanceof List) {
                    m4703a((List) obj, str, xmlSerializer);
                    return;
                }
                if (obj instanceof CharSequence) {
                    xmlSerializer.startTag(null, "string");
                    if (str != null) {
                        xmlSerializer.attribute(null, "name", str);
                    }
                    xmlSerializer.text(obj.toString());
                    xmlSerializer.endTag(null, "string");
                    return;
                }
                throw new RuntimeException(C1499a.m636v("writeValueXml: unable to write value ", obj));
            }
            str2 = "boolean";
        }
        xmlSerializer.startTag(null, str2);
        if (str != null) {
            xmlSerializer.attribute(null, "name", str);
        }
        xmlSerializer.attribute(null, "value", obj.toString());
        xmlSerializer.endTag(null, str2);
    }

    /* renamed from: a */
    public static final HashMap m4700a(InputStream inputStream) {
        XmlPullParser newPullParser = Xml.newPullParser();
        newPullParser.setInput(inputStream, null);
        return (HashMap) m4698a(newPullParser, new String[1]);
    }

    /* renamed from: a */
    public static final HashMap m4701a(XmlPullParser xmlPullParser, String str, String[] strArr) {
        HashMap hashMap = new HashMap();
        int eventType = xmlPullParser.getEventType();
        do {
            if (eventType == 2) {
                Object m4709b = m4709b(xmlPullParser, strArr);
                if (strArr[0] != null) {
                    hashMap.put(strArr[0], m4709b);
                } else {
                    StringBuilder m586H = C1499a.m586H("Map value without name attribute: ");
                    m586H.append(xmlPullParser.getName());
                    throw new XmlPullParserException(m586H.toString());
                }
            } else if (eventType == 3) {
                if (xmlPullParser.getName().equals(str)) {
                    return hashMap;
                }
                StringBuilder m591M = C1499a.m591M("Expected ", str, " end tag at: ");
                m591M.append(xmlPullParser.getName());
                throw new XmlPullParserException(m591M.toString());
            }
            eventType = xmlPullParser.next();
        } while (eventType != 1);
        throw new XmlPullParserException(C1499a.m639y("Document ended before ", str, " end tag"));
    }

    /* renamed from: a */
    public static final ArrayList m4699a(XmlPullParser xmlPullParser, String str, String[] strArr) {
        ArrayList arrayList = new ArrayList();
        int eventType = xmlPullParser.getEventType();
        do {
            if (eventType == 2) {
                arrayList.add(m4709b(xmlPullParser, strArr));
            } else if (eventType == 3) {
                if (xmlPullParser.getName().equals(str)) {
                    return arrayList;
                }
                StringBuilder m591M = C1499a.m591M("Expected ", str, " end tag at: ");
                m591M.append(xmlPullParser.getName());
                throw new XmlPullParserException(m591M.toString());
            }
            eventType = xmlPullParser.next();
        } while (eventType != 1);
        throw new XmlPullParserException(C1499a.m639y("Document ended before ", str, " end tag"));
    }

    /* renamed from: a */
    public static final int[] m4708a(XmlPullParser xmlPullParser, String str, String[] strArr) {
        try {
            int[] iArr = new int[Integer.parseInt(xmlPullParser.getAttributeValue(null, "num"))];
            int i2 = 0;
            int eventType = xmlPullParser.getEventType();
            do {
                if (eventType == 2) {
                    if (xmlPullParser.getName().equals("item")) {
                        try {
                            iArr[i2] = Integer.parseInt(xmlPullParser.getAttributeValue(null, "value"));
                        } catch (NullPointerException unused) {
                            throw new XmlPullParserException("Need value attribute in item");
                        } catch (NumberFormatException unused2) {
                            throw new XmlPullParserException("Not a number in value attribute in item");
                        }
                    } else {
                        StringBuilder m586H = C1499a.m586H("Expected item tag at: ");
                        m586H.append(xmlPullParser.getName());
                        throw new XmlPullParserException(m586H.toString());
                    }
                } else if (eventType == 3) {
                    if (xmlPullParser.getName().equals(str)) {
                        return iArr;
                    }
                    if (!xmlPullParser.getName().equals("item")) {
                        StringBuilder m591M = C1499a.m591M("Expected ", str, " end tag at: ");
                        m591M.append(xmlPullParser.getName());
                        throw new XmlPullParserException(m591M.toString());
                    }
                    i2++;
                }
                eventType = xmlPullParser.next();
            } while (eventType != 1);
            throw new XmlPullParserException(C1499a.m639y("Document ended before ", str, " end tag"));
        } catch (NullPointerException unused3) {
            throw new XmlPullParserException("Need num attribute in byte-array");
        } catch (NumberFormatException unused4) {
            throw new XmlPullParserException("Not a number in num attribute in byte-array");
        }
    }

    /* renamed from: a */
    public static final Object m4698a(XmlPullParser xmlPullParser, String[] strArr) {
        int eventType = xmlPullParser.getEventType();
        while (eventType != 2) {
            if (eventType == 3) {
                StringBuilder m586H = C1499a.m586H("Unexpected end tag at: ");
                m586H.append(xmlPullParser.getName());
                throw new XmlPullParserException(m586H.toString());
            }
            if (eventType != 4) {
                try {
                    eventType = xmlPullParser.next();
                    if (eventType == 1) {
                        throw new XmlPullParserException("Unexpected end of document");
                    }
                } catch (Exception unused) {
                    StringBuilder m586H2 = C1499a.m586H("Unexpected call next(): ");
                    m586H2.append(xmlPullParser.getName());
                    throw new XmlPullParserException(m586H2.toString());
                }
            } else {
                StringBuilder m586H3 = C1499a.m586H("Unexpected text: ");
                m586H3.append(xmlPullParser.getText());
                throw new XmlPullParserException(m586H3.toString());
            }
        }
        return m4709b(xmlPullParser, strArr);
    }
}
