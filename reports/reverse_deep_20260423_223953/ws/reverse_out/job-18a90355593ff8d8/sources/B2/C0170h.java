package B2;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/* JADX INFO: renamed from: B2.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0170h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f224a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f225b;

    public C0170h(String str, Map map) {
        String lowerCase;
        t2.j.f(str, "scheme");
        t2.j.f(map, "authParams");
        this.f225b = str;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry entry : map.entrySet()) {
            String str2 = (String) entry.getKey();
            String str3 = (String) entry.getValue();
            if (str2 != null) {
                Locale locale = Locale.US;
                t2.j.e(locale, "US");
                lowerCase = str2.toLowerCase(locale);
                t2.j.e(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
            } else {
                lowerCase = null;
            }
            linkedHashMap.put(lowerCase, str3);
        }
        Map mapUnmodifiableMap = Collections.unmodifiableMap(linkedHashMap);
        t2.j.e(mapUnmodifiableMap, "unmodifiableMap<String?, String>(newAuthParams)");
        this.f224a = mapUnmodifiableMap;
    }

    public final Charset a() {
        String str = (String) this.f224a.get("charset");
        if (str != null) {
            try {
                Charset charsetForName = Charset.forName(str);
                t2.j.e(charsetForName, "Charset.forName(charset)");
                return charsetForName;
            } catch (Exception unused) {
            }
        }
        Charset charset = StandardCharsets.ISO_8859_1;
        t2.j.e(charset, "ISO_8859_1");
        return charset;
    }

    public final String b() {
        return (String) this.f224a.get("realm");
    }

    public final String c() {
        return this.f225b;
    }

    public boolean equals(Object obj) {
        if (obj instanceof C0170h) {
            C0170h c0170h = (C0170h) obj;
            if (t2.j.b(c0170h.f225b, this.f225b) && t2.j.b(c0170h.f224a, this.f224a)) {
                return true;
            }
        }
        return false;
    }

    public int hashCode() {
        return ((899 + this.f225b.hashCode()) * 31) + this.f224a.hashCode();
    }

    public String toString() {
        return this.f225b + " authParams=" + this.f224a;
    }
}
