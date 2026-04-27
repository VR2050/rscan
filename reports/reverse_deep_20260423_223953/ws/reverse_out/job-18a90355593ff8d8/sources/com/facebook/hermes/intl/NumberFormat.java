package com.facebook.hermes.intl;

import com.facebook.hermes.intl.c;
import com.facebook.hermes.intl.g;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class NumberFormat {

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private static String[] f5867v = {"acre", "bit", "byte", "celsius", "centimeter", "day", "degree", "fahrenheit", "fluid-ounce", "foot", "gallon", "gigabit", "gigabyte", "gram", "hectare", "hour", "inch", "kilobit", "kilobyte", "kilogram", "kilometer", "liter", "megabit", "megabyte", "meter", "mile", "mile-scandinavian", "milliliter", "millimeter", "millisecond", "minute", "month", "ounce", "percent", "petabyte", "pound", "second", "stone", "terabit", "terabyte", "week", "yard", "year"};

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private c.h f5868a;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private c.i f5873f;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private c.f f5880m;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f5883p;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private c.b f5886s;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f5869b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private c.EnumC0094c f5870c = c.EnumC0094c.SYMBOL;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private c.d f5871d = c.d.STANDARD;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private String f5872e = null;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f5874g = true;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f5875h = -1;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f5876i = -1;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f5877j = -1;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f5878k = -1;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f5879l = -1;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private c.g f5881n = c.g.AUTO;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private String f5884q = null;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private c.e f5885r = null;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private A0.b f5887t = null;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private A0.b f5888u = null;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private c f5882o = new j();

    public NumberFormat(List<String> list, Map<String, Object> map) throws A0.e {
        a(list, map);
        this.f5882o.i(this.f5887t, this.f5883p ? "" : this.f5884q, this.f5868a, this.f5871d, this.f5885r, this.f5886s).j(this.f5869b, this.f5870c).k(this.f5874g).h(this.f5875h).d(this.f5880m, this.f5878k, this.f5879l).l(this.f5880m, this.f5876i, this.f5877j).g(this.f5881n).f(this.f5872e, this.f5873f);
    }

    private void a(List list, Map map) throws A0.e {
        Object objP;
        Object objP2;
        Object objQ = A0.d.q();
        g.a aVar = g.a.STRING;
        A0.d.c(objQ, "localeMatcher", g.c(map, "localeMatcher", aVar, A0.a.f16a, "best fit"));
        Object objC = g.c(map, "numberingSystem", aVar, A0.d.d(), A0.d.d());
        if (!A0.d.n(objC) && !b(A0.d.h(objC))) {
            throw new A0.e("Invalid numbering system !");
        }
        A0.d.c(objQ, "nu", objC);
        HashMap mapA = f.a(list, objQ, Collections.singletonList("nu"));
        A0.b bVar = (A0.b) A0.d.g(mapA).get("locale");
        this.f5887t = bVar;
        this.f5888u = bVar.e();
        Object objA = A0.d.a(mapA, "nu");
        if (A0.d.j(objA)) {
            this.f5883p = true;
            this.f5884q = this.f5882o.c(this.f5887t);
        } else {
            this.f5883p = false;
            this.f5884q = A0.d.h(objA);
        }
        h(map);
        if (this.f5868a == c.h.CURRENCY) {
            double dN = j.n(this.f5869b);
            objP = A0.d.p(dN);
            objP2 = A0.d.p(dN);
        } else {
            objP = A0.d.p(0.0d);
            objP2 = this.f5868a == c.h.PERCENT ? A0.d.p(0.0d) : A0.d.p(3.0d);
        }
        this.f5885r = (c.e) g.d(c.e.class, A0.d.h(g.c(map, "notation", aVar, new String[]{"standard", "scientific", "engineering", "compact"}, "standard")));
        g(map, objP, objP2);
        Object objC2 = g.c(map, "compactDisplay", aVar, new String[]{"short", "long"}, "short");
        if (this.f5885r == c.e.COMPACT) {
            this.f5886s = (c.b) g.d(c.b.class, A0.d.h(objC2));
        }
        this.f5874g = A0.d.e(g.c(map, "useGrouping", g.a.BOOLEAN, A0.d.d(), A0.d.o(true)));
        this.f5881n = (c.g) g.d(c.g.class, A0.d.h(g.c(map, "signDisplay", aVar, new String[]{"auto", "never", "always", "exceptZero"}, "auto")));
    }

    private boolean b(String str) {
        return A0.c.e(str, 0, str.length() - 1);
    }

    private boolean c(String str) {
        return Arrays.binarySearch(f5867v, str) >= 0;
    }

    private boolean d(String str) {
        return f(str).matches("^[A-Z][A-Z][A-Z]$");
    }

    private boolean e(String str) {
        if (c(str)) {
            return true;
        }
        int iIndexOf = str.indexOf("-per-");
        return iIndexOf >= 0 && str.indexOf("-per-", iIndexOf + 1) < 0 && c(str.substring(0, iIndexOf)) && c(str.substring(iIndexOf + 5));
    }

    private String f(String str) {
        StringBuilder sb = new StringBuilder(str.length());
        for (int i3 = 0; i3 < str.length(); i3++) {
            char cCharAt = str.charAt(i3);
            if (cCharAt < 'a' || cCharAt > 'z') {
                sb.append(cCharAt);
            } else {
                sb.append((char) (cCharAt - ' '));
            }
        }
        return sb.toString();
    }

    private void g(Map map, Object obj, Object obj2) throws A0.e {
        Object objB = g.b(map, "minimumIntegerDigits", A0.d.p(1.0d), A0.d.p(21.0d), A0.d.p(1.0d));
        Object objA = A0.d.a(map, "minimumFractionDigits");
        Object objA2 = A0.d.a(map, "maximumFractionDigits");
        Object objA3 = A0.d.a(map, "minimumSignificantDigits");
        Object objA4 = A0.d.a(map, "maximumSignificantDigits");
        this.f5875h = (int) Math.floor(A0.d.f(objB));
        if (!A0.d.n(objA3) || !A0.d.n(objA4)) {
            this.f5880m = c.f.SIGNIFICANT_DIGITS;
            Object objA5 = g.a("minimumSignificantDigits", objA3, A0.d.p(1.0d), A0.d.p(21.0d), A0.d.p(1.0d));
            Object objA6 = g.a("maximumSignificantDigits", objA4, objA5, A0.d.p(21.0d), A0.d.p(21.0d));
            this.f5878k = (int) Math.floor(A0.d.f(objA5));
            this.f5879l = (int) Math.floor(A0.d.f(objA6));
            return;
        }
        if (A0.d.n(objA) && A0.d.n(objA2)) {
            c.e eVar = this.f5885r;
            if (eVar == c.e.COMPACT) {
                this.f5880m = c.f.COMPACT_ROUNDING;
                return;
            }
            if (eVar == c.e.ENGINEERING) {
                this.f5880m = c.f.FRACTION_DIGITS;
                this.f5877j = 5;
                return;
            } else {
                this.f5880m = c.f.FRACTION_DIGITS;
                this.f5876i = (int) Math.floor(A0.d.f(obj));
                this.f5877j = (int) Math.floor(A0.d.f(obj2));
                return;
            }
        }
        this.f5880m = c.f.FRACTION_DIGITS;
        Object objA7 = g.a("minimumFractionDigits", objA, A0.d.p(0.0d), A0.d.p(20.0d), A0.d.d());
        Object objA8 = g.a("maximumFractionDigits", objA2, A0.d.p(0.0d), A0.d.p(20.0d), A0.d.d());
        if (A0.d.n(objA7)) {
            objA7 = A0.d.p(Math.min(A0.d.f(obj), A0.d.f(objA8)));
        } else if (A0.d.n(objA8)) {
            objA8 = A0.d.p(Math.max(A0.d.f(obj2), A0.d.f(objA7)));
        } else if (A0.d.f(objA7) > A0.d.f(objA8)) {
            throw new A0.e("minimumFractionDigits is greater than maximumFractionDigits");
        }
        this.f5876i = (int) Math.floor(A0.d.f(objA7));
        this.f5877j = (int) Math.floor(A0.d.f(objA8));
    }

    private void h(Map map) throws A0.e {
        g.a aVar = g.a.STRING;
        this.f5868a = (c.h) g.d(c.h.class, A0.d.h(g.c(map, "style", aVar, new String[]{"decimal", "percent", "currency", "unit"}, "decimal")));
        Object objC = g.c(map, "currency", aVar, A0.d.d(), A0.d.d());
        if (A0.d.n(objC)) {
            if (this.f5868a == c.h.CURRENCY) {
                throw new A0.e("Expected currency style !");
            }
        } else if (!d(A0.d.h(objC))) {
            throw new A0.e("Malformed currency code !");
        }
        Object objC2 = g.c(map, "currencyDisplay", aVar, new String[]{"symbol", "narrowSymbol", "code", "name"}, "symbol");
        Object objC3 = g.c(map, "currencySign", aVar, new String[]{"accounting", "standard"}, "standard");
        Object objC4 = g.c(map, "unit", aVar, A0.d.d(), A0.d.d());
        if (A0.d.n(objC4)) {
            if (this.f5868a == c.h.UNIT) {
                throw new A0.e("Expected unit !");
            }
        } else if (!e(A0.d.h(objC4))) {
            throw new A0.e("Malformed unit identifier !");
        }
        Object objC5 = g.c(map, "unitDisplay", aVar, new String[]{"long", "short", "narrow"}, "short");
        c.h hVar = this.f5868a;
        if (hVar == c.h.CURRENCY) {
            this.f5869b = f(A0.d.h(objC));
            this.f5870c = (c.EnumC0094c) g.d(c.EnumC0094c.class, A0.d.h(objC2));
            this.f5871d = (c.d) g.d(c.d.class, A0.d.h(objC3));
        } else if (hVar == c.h.UNIT) {
            this.f5872e = A0.d.h(objC4);
            this.f5873f = (c.i) g.d(c.i.class, A0.d.h(objC5));
        }
    }

    public static List<String> supportedLocalesOf(List<String> list, Map<String, Object> map) {
        String strH = A0.d.h(g.c(map, "localeMatcher", g.a.STRING, A0.a.f16a, "best fit"));
        String[] strArr = new String[list.size()];
        return strH.equals("best fit") ? Arrays.asList(e.d((String[]) list.toArray(strArr))) : Arrays.asList(e.h((String[]) list.toArray(strArr)));
    }

    public String format(double d3) {
        return this.f5882o.b(d3);
    }

    public List<Map<String, String>> formatToParts(double d3) {
        ArrayList arrayList = new ArrayList();
        AttributedCharacterIterator attributedCharacterIteratorA = this.f5882o.a(d3);
        StringBuilder sb = new StringBuilder();
        for (char cFirst = attributedCharacterIteratorA.first(); cFirst != 65535; cFirst = attributedCharacterIteratorA.next()) {
            sb.append(cFirst);
            if (attributedCharacterIteratorA.getIndex() + 1 == attributedCharacterIteratorA.getRunLimit()) {
                Iterator<AttributedCharacterIterator.Attribute> it = attributedCharacterIteratorA.getAttributes().keySet().iterator();
                String strE = it.hasNext() ? this.f5882o.e(it.next(), d3) : "literal";
                String string = sb.toString();
                sb.setLength(0);
                HashMap map = new HashMap();
                map.put("type", strE);
                map.put("value", string);
                arrayList.add(map);
            }
        }
        return arrayList;
    }

    public Map<String, Object> resolvedOptions() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("locale", this.f5888u.a());
        linkedHashMap.put("numberingSystem", this.f5884q);
        linkedHashMap.put("style", this.f5868a.toString());
        c.h hVar = this.f5868a;
        if (hVar == c.h.CURRENCY) {
            linkedHashMap.put("currency", this.f5869b);
            linkedHashMap.put("currencyDisplay", this.f5870c.toString());
            linkedHashMap.put("currencySign", this.f5871d.toString());
        } else if (hVar == c.h.UNIT) {
            linkedHashMap.put("unit", this.f5872e);
            linkedHashMap.put("unitDisplay", this.f5873f.toString());
        }
        int i3 = this.f5875h;
        if (i3 != -1) {
            linkedHashMap.put("minimumIntegerDigits", Integer.valueOf(i3));
        }
        c.f fVar = this.f5880m;
        if (fVar == c.f.SIGNIFICANT_DIGITS) {
            int i4 = this.f5879l;
            if (i4 != -1) {
                linkedHashMap.put("maximumSignificantDigits", Integer.valueOf(i4));
            }
            int i5 = this.f5878k;
            if (i5 != -1) {
                linkedHashMap.put("minimumSignificantDigits", Integer.valueOf(i5));
            }
        } else if (fVar == c.f.FRACTION_DIGITS) {
            int i6 = this.f5876i;
            if (i6 != -1) {
                linkedHashMap.put("minimumFractionDigits", Integer.valueOf(i6));
            }
            int i7 = this.f5877j;
            if (i7 != -1) {
                linkedHashMap.put("maximumFractionDigits", Integer.valueOf(i7));
            }
        }
        linkedHashMap.put("useGrouping", Boolean.valueOf(this.f5874g));
        linkedHashMap.put("notation", this.f5885r.toString());
        if (this.f5885r == c.e.COMPACT) {
            linkedHashMap.put("compactDisplay", this.f5886s.toString());
        }
        linkedHashMap.put("signDisplay", this.f5881n.toString());
        return linkedHashMap;
    }
}
