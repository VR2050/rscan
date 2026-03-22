package p005b.p113c0.p114a.p130l;

import android.text.TextUtils;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.util.BitSet;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import p005b.p113c0.p114a.p115g.C1417c;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c0.a.l.h */
/* loaded from: classes2.dex */
public class C1496h implements Comparable<C1496h>, Serializable {

    /* renamed from: c */
    public static final BitSet f1511c;

    /* renamed from: e */
    public final String f1512e;

    /* renamed from: f */
    public final String f1513f;

    /* renamed from: g */
    public final Map<String, String> f1514g;

    static {
        BitSet bitSet = new BitSet(128);
        for (int i2 = 0; i2 <= 31; i2++) {
            bitSet.set(i2);
        }
        bitSet.set(127);
        BitSet bitSet2 = new BitSet(128);
        bitSet2.set(40);
        bitSet2.set(41);
        bitSet2.set(60);
        bitSet2.set(62);
        bitSet2.set(64);
        bitSet2.set(44);
        bitSet2.set(59);
        bitSet2.set(58);
        bitSet2.set(92);
        bitSet2.set(34);
        bitSet2.set(47);
        bitSet2.set(91);
        bitSet2.set(93);
        bitSet2.set(63);
        bitSet2.set(61);
        bitSet2.set(123);
        bitSet2.set(125);
        bitSet2.set(32);
        bitSet2.set(9);
        BitSet bitSet3 = new BitSet(128);
        f1511c = bitSet3;
        bitSet3.set(0, 128);
        bitSet3.andNot(bitSet);
        bitSet3.andNot(bitSet2);
    }

    public C1496h(String str, String str2, Map<String, String> map) {
        m572b(str);
        m572b(str2);
        Locale locale = Locale.ENGLISH;
        this.f1512e = str.toLowerCase(locale);
        this.f1513f = str2.toLowerCase(locale);
        if (map == null || map.isEmpty()) {
            this.f1514g = Collections.emptyMap();
            return;
        }
        C1493e c1493e = new C1493e(map.size(), locale);
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            mo569a(key, value);
            c1493e.put(key, value);
        }
        this.f1514g = Collections.unmodifiableMap(c1493e);
    }

    /* renamed from: i */
    public static C1496h m571i(String str) {
        if (TextUtils.isEmpty(str)) {
            throw new C1417c(str, "[mimeType] must not be empty");
        }
        int indexOf = str.indexOf(59);
        String trim = (indexOf >= 0 ? str.substring(0, indexOf) : str).trim();
        if (trim.isEmpty()) {
            throw new C1417c(str, "'contentType' must not be empty");
        }
        if ("*".equals(trim)) {
            trim = "*/*";
        }
        int indexOf2 = trim.indexOf(47);
        if (indexOf2 == -1) {
            throw new C1417c(str, "does not contain '/'");
        }
        if (indexOf2 == trim.length() - 1) {
            throw new C1417c(str, "does not contain subtype after '/'");
        }
        String substring = trim.substring(0, indexOf2);
        String substring2 = trim.substring(indexOf2 + 1, trim.length());
        if ("*".equals(substring) && !"*".equals(substring2)) {
            throw new C1417c(str, "wildcard type is legal only in '*/*' (all mime types)");
        }
        LinkedHashMap linkedHashMap = null;
        while (true) {
            int i2 = indexOf + 1;
            int i3 = i2;
            boolean z = false;
            while (i3 < str.length()) {
                char charAt = str.charAt(i3);
                if (charAt == ';') {
                    if (!z) {
                        break;
                    }
                } else if (charAt == '\"') {
                    z = !z;
                }
                i3++;
            }
            String trim2 = str.substring(i2, i3).trim();
            if (trim2.length() > 0) {
                if (linkedHashMap == null) {
                    linkedHashMap = new LinkedHashMap(4);
                }
                int indexOf3 = trim2.indexOf(61);
                if (indexOf3 >= 0) {
                    linkedHashMap.put(trim2.substring(0, indexOf3), trim2.substring(indexOf3 + 1, trim2.length()));
                }
            }
            if (i3 >= str.length()) {
                try {
                    return new C1496h(substring, substring2, linkedHashMap);
                } catch (UnsupportedCharsetException e2) {
                    StringBuilder m586H = C1499a.m586H("unsupported charset '");
                    m586H.append(e2.getCharsetName());
                    m586H.append("'");
                    throw new C1417c(str, m586H.toString());
                } catch (IllegalArgumentException e3) {
                    throw new C1417c(str, e3.getMessage());
                }
            }
            indexOf = i3;
        }
    }

    /* renamed from: a */
    public void mo569a(String str, String str2) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("'attribute' must not be empty.");
        }
        if (TextUtils.isEmpty(str2)) {
            throw new IllegalArgumentException("'value' must not be empty.");
        }
        m572b(str);
        if ("charset".equals(str)) {
            Charset.forName(m578h(str2));
        } else {
            if (m575e(str2)) {
                return;
            }
            m572b(str2);
        }
    }

    /* renamed from: b */
    public final void m572b(String str) {
        for (int i2 = 0; i2 < str.length(); i2++) {
            char charAt = str.charAt(i2);
            if (!f1511c.get(charAt)) {
                throw new IllegalArgumentException("Invalid token character '" + charAt + "' in token \"" + str + "\"");
            }
        }
    }

    /* renamed from: c */
    public boolean m573c(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1496h)) {
            return false;
        }
        C1496h c1496h = (C1496h) obj;
        return this.f1512e.equalsIgnoreCase(c1496h.f1512e) && this.f1513f.equalsIgnoreCase(c1496h.f1513f);
    }

    @Override // java.lang.Comparable
    public int compareTo(C1496h c1496h) {
        C1496h c1496h2 = c1496h;
        int compareToIgnoreCase = this.f1512e.compareToIgnoreCase(c1496h2.f1512e);
        if (compareToIgnoreCase != 0) {
            return compareToIgnoreCase;
        }
        int compareToIgnoreCase2 = this.f1513f.compareToIgnoreCase(c1496h2.f1513f);
        if (compareToIgnoreCase2 != 0) {
            return compareToIgnoreCase2;
        }
        int size = this.f1514g.size() - c1496h2.f1514g.size();
        if (size != 0) {
            return size;
        }
        Comparator comparator = String.CASE_INSENSITIVE_ORDER;
        TreeSet treeSet = new TreeSet(comparator);
        treeSet.addAll(this.f1514g.keySet());
        TreeSet treeSet2 = new TreeSet(comparator);
        treeSet2.addAll(c1496h2.f1514g.keySet());
        Iterator it = treeSet.iterator();
        Iterator it2 = treeSet2.iterator();
        while (it.hasNext()) {
            String str = (String) it.next();
            String str2 = (String) it2.next();
            int compareToIgnoreCase3 = str.compareToIgnoreCase(str2);
            if (compareToIgnoreCase3 != 0) {
                return compareToIgnoreCase3;
            }
            String str3 = this.f1514g.get(str);
            String str4 = c1496h2.f1514g.get(str2);
            if (str4 == null) {
                str4 = "";
            }
            int compareTo = str3.compareTo(str4);
            if (compareTo != 0) {
                return compareTo;
            }
        }
        return 0;
    }

    /* renamed from: d */
    public Charset m574d() {
        String str = this.f1514g.get("charset");
        if (str != null) {
            return Charset.forName(m578h(str));
        }
        return null;
    }

    /* renamed from: e */
    public final boolean m575e(String str) {
        if (str.length() < 2) {
            return false;
        }
        return (str.startsWith("\"") && str.endsWith("\"")) || (str.startsWith("'") && str.endsWith("'"));
    }

    public boolean equals(Object obj) {
        String str;
        String str2;
        if (!m573c(obj)) {
            return false;
        }
        C1496h c1496h = (C1496h) obj;
        if (this.f1514g.size() != c1496h.f1514g.size()) {
            return false;
        }
        Iterator<String> it = this.f1514g.keySet().iterator();
        do {
            if (it.hasNext()) {
                String next = it.next();
                if (!c1496h.f1514g.containsKey(next)) {
                    return false;
                }
                if ("charset".equals(next)) {
                    Charset m574d = m574d();
                    Charset m574d2 = c1496h.m574d();
                    if (m574d == null || !m574d.equals(m574d2)) {
                        return false;
                    }
                } else {
                    str = this.f1514g.get(next);
                    str2 = c1496h.f1514g.get(next);
                    if (str == null) {
                        return false;
                    }
                }
            }
            return true;
        } while (str.equals(str2));
        return false;
    }

    /* renamed from: f */
    public boolean m576f() {
        return "*".equals(this.f1513f) || this.f1513f.startsWith("*+");
    }

    /* renamed from: g */
    public boolean m577g() {
        return "*".equals(this.f1512e);
    }

    /* renamed from: h */
    public String m578h(String str) {
        if (str == null) {
            return null;
        }
        return m575e(str) ? str.substring(1, str.length() - 1) : str;
    }

    public int hashCode() {
        return this.f1514g.hashCode() + C1499a.m598T(this.f1513f, this.f1512e.hashCode() * 31, 31);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.f1512e);
        sb.append('/');
        sb.append(this.f1513f);
        for (Map.Entry<String, String> entry : this.f1514g.entrySet()) {
            sb.append(';');
            sb.append(entry.getKey());
            sb.append('=');
            sb.append(entry.getValue());
        }
        return sb.toString();
    }
}
