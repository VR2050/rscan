package com.facebook.hermes.intl;

import com.facebook.hermes.intl.b;
import com.facebook.hermes.intl.g;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/* JADX INFO: loaded from: classes.dex */
public class DateTimeFormat {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f5848d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private String f5849e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f5850f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private String f5851g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Object f5852h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private b.g f5853i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private b.e f5854j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private b.m f5855k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private b.d f5856l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private b.n f5857m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private b.i f5858n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private b.c f5859o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private b.f f5860p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private b.h f5861q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private b.j f5862r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private b.l f5863s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private b.EnumC0093b f5864t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private b.k f5865u;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private A0.b f5846b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private A0.b f5847c = null;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Object f5866v = null;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    b f5845a = new i();

    public DateTimeFormat(List<String> list, Map<String, Object> map) throws A0.e {
        c(list, map);
        this.f5845a.g(this.f5846b, this.f5848d ? "" : this.f5849e, this.f5850f ? "" : this.f5851g, this.f5854j, this.f5855k, this.f5856l, this.f5857m, this.f5858n, this.f5859o, this.f5860p, this.f5861q, this.f5862r, this.f5863s, this.f5853i, this.f5866v, this.f5864t, this.f5865u, this.f5852h);
    }

    private Object a() {
        return this.f5845a.h(this.f5846b);
    }

    private Object b(Object obj, String str, String str2) throws A0.e {
        if (!A0.d.l(obj)) {
            throw new A0.e("Invalid options object !");
        }
        boolean z3 = true;
        if (str.equals("date") || str.equals("any")) {
            String[] strArr = {"weekday", "year", "month", "day"};
            for (int i3 = 0; i3 < 4; i3++) {
                if (!A0.d.n(A0.d.a(obj, strArr[i3]))) {
                    z3 = false;
                }
            }
        }
        if (str.equals("time") || str.equals("any")) {
            String[] strArr2 = {"hour", "minute", "second"};
            for (int i4 = 0; i4 < 3; i4++) {
                if (!A0.d.n(A0.d.a(obj, strArr2[i4]))) {
                    z3 = false;
                }
            }
        }
        if (!A0.d.n(A0.d.a(obj, "dateStyle")) || !A0.d.n(A0.d.a(obj, "timeStyle"))) {
            z3 = false;
        }
        if (z3 && (str2.equals("date") || str2.equals("all"))) {
            String[] strArr3 = {"year", "month", "day"};
            for (int i5 = 0; i5 < 3; i5++) {
                A0.d.c(obj, strArr3[i5], "numeric");
            }
        }
        if (z3 && (str2.equals("time") || str2.equals("all"))) {
            String[] strArr4 = {"hour", "minute", "second"};
            for (int i6 = 0; i6 < 3; i6++) {
                A0.d.c(obj, strArr4[i6], "numeric");
            }
        }
        return obj;
    }

    private void c(List list, Map map) throws A0.e {
        List listAsList = Arrays.asList("ca", "nu", "hc");
        Object objB = b(map, "any", "date");
        Object objQ = A0.d.q();
        g.a aVar = g.a.STRING;
        A0.d.c(objQ, "localeMatcher", g.c(objB, "localeMatcher", aVar, A0.a.f16a, "best fit"));
        Object objC = g.c(objB, "calendar", aVar, A0.d.d(), A0.d.d());
        if (!A0.d.n(objC) && !d(A0.d.h(objC))) {
            throw new A0.e("Invalid calendar option !");
        }
        A0.d.c(objQ, "ca", objC);
        Object objC2 = g.c(objB, "numberingSystem", aVar, A0.d.d(), A0.d.d());
        if (!A0.d.n(objC2) && !d(A0.d.h(objC2))) {
            throw new A0.e("Invalid numbering system !");
        }
        A0.d.c(objQ, "nu", objC2);
        Object objC3 = g.c(objB, "hour12", g.a.BOOLEAN, A0.d.d(), A0.d.d());
        Object objC4 = g.c(objB, "hourCycle", aVar, new String[]{"h11", "h12", "h23", "h24"}, A0.d.d());
        if (!A0.d.n(objC3)) {
            objC4 = A0.d.b();
        }
        A0.d.c(objQ, "hc", objC4);
        HashMap mapA = f.a(list, objQ, listAsList);
        A0.b bVar = (A0.b) A0.d.g(mapA).get("locale");
        this.f5846b = bVar;
        this.f5847c = bVar.e();
        Object objA = A0.d.a(mapA, "ca");
        if (A0.d.j(objA)) {
            this.f5848d = true;
            this.f5849e = this.f5845a.e(this.f5846b);
        } else {
            this.f5848d = false;
            this.f5849e = A0.d.h(objA);
        }
        Object objA2 = A0.d.a(mapA, "nu");
        if (A0.d.j(objA2)) {
            this.f5850f = true;
            this.f5851g = this.f5845a.c(this.f5846b);
        } else {
            this.f5850f = false;
            this.f5851g = A0.d.h(objA2);
        }
        Object objA3 = A0.d.a(mapA, "hc");
        Object objA4 = A0.d.a(objB, "timeZone");
        this.f5866v = A0.d.n(objA4) ? a() : e(objA4.toString());
        this.f5854j = (b.e) g.d(b.e.class, A0.d.h(g.c(objB, "formatMatcher", aVar, new String[]{"basic", "best fit"}, "best fit")));
        this.f5855k = (b.m) g.d(b.m.class, g.c(objB, "weekday", aVar, new String[]{"long", "short", "narrow"}, A0.d.d()));
        this.f5856l = (b.d) g.d(b.d.class, g.c(objB, "era", aVar, new String[]{"long", "short", "narrow"}, A0.d.d()));
        this.f5857m = (b.n) g.d(b.n.class, g.c(objB, "year", aVar, new String[]{"numeric", "2-digit"}, A0.d.d()));
        this.f5858n = (b.i) g.d(b.i.class, g.c(objB, "month", aVar, new String[]{"numeric", "2-digit", "long", "short", "narrow"}, A0.d.d()));
        this.f5859o = (b.c) g.d(b.c.class, g.c(objB, "day", aVar, new String[]{"numeric", "2-digit"}, A0.d.d()));
        Object objC5 = g.c(objB, "hour", aVar, new String[]{"numeric", "2-digit"}, A0.d.d());
        this.f5860p = (b.f) g.d(b.f.class, objC5);
        this.f5861q = (b.h) g.d(b.h.class, g.c(objB, "minute", aVar, new String[]{"numeric", "2-digit"}, A0.d.d()));
        this.f5862r = (b.j) g.d(b.j.class, g.c(objB, "second", aVar, new String[]{"numeric", "2-digit"}, A0.d.d()));
        this.f5863s = (b.l) g.d(b.l.class, g.c(objB, "timeZoneName", aVar, new String[]{"long", "longOffset", "longGeneric", "short", "shortOffset", "shortGeneric"}, A0.d.d()));
        this.f5864t = (b.EnumC0093b) g.d(b.EnumC0093b.class, g.c(objB, "dateStyle", aVar, new String[]{"full", "long", "medium", "short"}, A0.d.d()));
        Object objC6 = g.c(objB, "timeStyle", aVar, new String[]{"full", "long", "medium", "short"}, A0.d.d());
        this.f5865u = (b.k) g.d(b.k.class, objC6);
        if (A0.d.n(objC5) && A0.d.n(objC6)) {
            this.f5853i = b.g.UNDEFINED;
        } else {
            b.g gVarD = this.f5845a.d(this.f5846b);
            b.g gVar = A0.d.j(objA3) ? gVarD : (b.g) g.d(b.g.class, objA3);
            if (!A0.d.n(objC3)) {
                if (A0.d.e(objC3)) {
                    gVar = b.g.H11;
                    if (gVarD != gVar && gVarD != b.g.H23) {
                        gVar = b.g.H12;
                    }
                } else {
                    gVar = (gVarD == b.g.H11 || gVarD == b.g.H23) ? b.g.H23 : b.g.H24;
                }
            }
            this.f5853i = gVar;
        }
        this.f5852h = objC3;
    }

    private boolean d(String str) {
        return A0.c.e(str, 0, str.length() - 1);
    }

    public static List<String> supportedLocalesOf(List<String> list, Map<String, Object> map) {
        String strH = A0.d.h(g.c(map, "localeMatcher", g.a.STRING, A0.a.f16a, "best fit"));
        String[] strArr = new String[list.size()];
        return strH.equals("best fit") ? Arrays.asList(e.d((String[]) list.toArray(strArr))) : Arrays.asList(e.h((String[]) list.toArray(strArr)));
    }

    public String e(String str) throws A0.e {
        for (String str2 : TimeZone.getAvailableIDs()) {
            if (f(str2).equals(f(str))) {
                return str2;
            }
        }
        throw new A0.e("Invalid timezone name!");
    }

    public String f(String str) {
        StringBuilder sb = new StringBuilder(str.length());
        for (int i3 = 0; i3 < str.length(); i3++) {
            char cCharAt = str.charAt(i3);
            if (cCharAt < 'A' || cCharAt > 'Z') {
                sb.append(cCharAt);
            } else {
                sb.append((char) (cCharAt + ' '));
            }
        }
        return sb.toString();
    }

    public String format(double d3) {
        return this.f5845a.b(d3);
    }

    public List<Map<String, String>> formatToParts(double d3) {
        ArrayList arrayList = new ArrayList();
        AttributedCharacterIterator attributedCharacterIteratorA = this.f5845a.a(d3);
        StringBuilder sb = new StringBuilder();
        for (char cFirst = attributedCharacterIteratorA.first(); cFirst != 65535; cFirst = attributedCharacterIteratorA.next()) {
            sb.append(cFirst);
            if (attributedCharacterIteratorA.getIndex() + 1 == attributedCharacterIteratorA.getRunLimit()) {
                Iterator<AttributedCharacterIterator.Attribute> it = attributedCharacterIteratorA.getAttributes().keySet().iterator();
                String strF = it.hasNext() ? this.f5845a.f(it.next(), sb.toString()) : "literal";
                String string = sb.toString();
                sb.setLength(0);
                HashMap map = new HashMap();
                map.put("type", strF);
                map.put("value", string);
                arrayList.add(map);
            }
        }
        return arrayList;
    }

    public Map<String, Object> resolvedOptions() {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("locale", this.f5847c.a());
        linkedHashMap.put("numberingSystem", this.f5851g);
        linkedHashMap.put("calendar", this.f5849e);
        linkedHashMap.put("timeZone", this.f5866v);
        b.g gVar = this.f5853i;
        if (gVar != b.g.UNDEFINED) {
            linkedHashMap.put("hourCycle", gVar.toString());
            b.g gVar2 = this.f5853i;
            if (gVar2 == b.g.H11 || gVar2 == b.g.H12) {
                linkedHashMap.put("hour12", Boolean.TRUE);
            } else {
                linkedHashMap.put("hour12", Boolean.FALSE);
            }
        }
        b.m mVar = this.f5855k;
        if (mVar != b.m.UNDEFINED) {
            linkedHashMap.put("weekday", mVar.toString());
        }
        b.d dVar = this.f5856l;
        if (dVar != b.d.UNDEFINED) {
            linkedHashMap.put("era", dVar.toString());
        }
        b.n nVar = this.f5857m;
        if (nVar != b.n.UNDEFINED) {
            linkedHashMap.put("year", nVar.toString());
        }
        b.i iVar = this.f5858n;
        if (iVar != b.i.UNDEFINED) {
            linkedHashMap.put("month", iVar.toString());
        }
        b.c cVar = this.f5859o;
        if (cVar != b.c.UNDEFINED) {
            linkedHashMap.put("day", cVar.toString());
        }
        b.f fVar = this.f5860p;
        if (fVar != b.f.UNDEFINED) {
            linkedHashMap.put("hour", fVar.toString());
        }
        b.h hVar = this.f5861q;
        if (hVar != b.h.UNDEFINED) {
            linkedHashMap.put("minute", hVar.toString());
        }
        b.j jVar = this.f5862r;
        if (jVar != b.j.UNDEFINED) {
            linkedHashMap.put("second", jVar.toString());
        }
        b.l lVar = this.f5863s;
        if (lVar != b.l.UNDEFINED) {
            linkedHashMap.put("timeZoneName", lVar.toString());
        }
        b.EnumC0093b enumC0093b = this.f5864t;
        if (enumC0093b != b.EnumC0093b.UNDEFINED) {
            linkedHashMap.put("dateStyle", enumC0093b.toString());
        }
        b.k kVar = this.f5865u;
        if (kVar != b.k.UNDEFINED) {
            linkedHashMap.put("timeStyle", kVar.toString());
        }
        return linkedHashMap;
    }
}
