package B2;

import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.internal.DefaultConstructorMarker;
import okhttp3.internal.publicsuffix.PublicSuffixDatabase;

/* JADX INFO: loaded from: classes.dex */
public final class m {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f370a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f371b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final long f372c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f373d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final String f374e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f375f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f376g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final boolean f377h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f378i;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final b f369n = new b(null);

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final Pattern f365j = Pattern.compile("(\\d{2,4})[^\\d]*");

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final Pattern f366k = Pattern.compile("(?i)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec).*");

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final Pattern f367l = Pattern.compile("(\\d{1,2})[^\\d]*");

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final Pattern f368m = Pattern.compile("(\\d{1,2}):(\\d{1,2}):(\\d{1,2})[^\\d]*");

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private String f379a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private String f380b;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private String f382d;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f384f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f385g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private boolean f386h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private boolean f387i;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private long f381c = 253402300799999L;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private String f383e = "/";

        private final a c(String str, boolean z3) {
            String strE = C2.a.e(str);
            if (strE != null) {
                this.f382d = strE;
                this.f387i = z3;
                return this;
            }
            throw new IllegalArgumentException("unexpected domain: " + str);
        }

        public final m a() {
            String str = this.f379a;
            if (str == null) {
                throw new NullPointerException("builder.name == null");
            }
            String str2 = this.f380b;
            if (str2 == null) {
                throw new NullPointerException("builder.value == null");
            }
            long j3 = this.f381c;
            String str3 = this.f382d;
            if (str3 != null) {
                return new m(str, str2, j3, str3, this.f383e, this.f384f, this.f385g, this.f386h, this.f387i, null);
            }
            throw new NullPointerException("builder.domain == null");
        }

        public final a b(String str) {
            t2.j.f(str, "domain");
            return c(str, false);
        }

        public final a d(String str) {
            t2.j.f(str, "name");
            if (!t2.j.b(z2.g.n0(str).toString(), str)) {
                throw new IllegalArgumentException("name is not trimmed");
            }
            this.f379a = str;
            return this;
        }

        public final a e(String str) {
            t2.j.f(str, "value");
            if (!t2.j.b(z2.g.n0(str).toString(), str)) {
                throw new IllegalArgumentException("value is not trimmed");
            }
            this.f380b = str;
            return this;
        }
    }

    public static final class b {
        private b() {
        }

        private final int a(String str, int i3, int i4, boolean z3) {
            while (i3 < i4) {
                char cCharAt = str.charAt(i3);
                if (((cCharAt < ' ' && cCharAt != '\t') || cCharAt >= 127 || ('0' <= cCharAt && '9' >= cCharAt) || (('a' <= cCharAt && 'z' >= cCharAt) || (('A' <= cCharAt && 'Z' >= cCharAt) || cCharAt == ':'))) == (!z3)) {
                    return i3;
                }
                i3++;
            }
            return i4;
        }

        private final boolean b(String str, String str2) {
            if (t2.j.b(str, str2)) {
                return true;
            }
            return z2.g.i(str, str2, false, 2, null) && str.charAt((str.length() - str2.length()) - 1) == '.' && !C2.c.f(str);
        }

        private final String f(String str) {
            if (z2.g.i(str, ".", false, 2, null)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            String strE = C2.a.e(z2.g.Y(str, "."));
            if (strE != null) {
                return strE;
            }
            throw new IllegalArgumentException();
        }

        private final long g(String str, int i3, int i4) {
            int iA = a(str, i3, i4, false);
            Matcher matcher = m.f368m.matcher(str);
            int i5 = -1;
            int i6 = -1;
            int i7 = -1;
            int iJ = -1;
            int i8 = -1;
            int i9 = -1;
            while (iA < i4) {
                int iA2 = a(str, iA + 1, i4, true);
                matcher.region(iA, iA2);
                if (i6 == -1 && matcher.usePattern(m.f368m).matches()) {
                    String strGroup = matcher.group(1);
                    t2.j.e(strGroup, "matcher.group(1)");
                    i6 = Integer.parseInt(strGroup);
                    String strGroup2 = matcher.group(2);
                    t2.j.e(strGroup2, "matcher.group(2)");
                    i8 = Integer.parseInt(strGroup2);
                    String strGroup3 = matcher.group(3);
                    t2.j.e(strGroup3, "matcher.group(3)");
                    i9 = Integer.parseInt(strGroup3);
                } else if (i7 == -1 && matcher.usePattern(m.f367l).matches()) {
                    String strGroup4 = matcher.group(1);
                    t2.j.e(strGroup4, "matcher.group(1)");
                    i7 = Integer.parseInt(strGroup4);
                } else if (iJ == -1 && matcher.usePattern(m.f366k).matches()) {
                    String strGroup5 = matcher.group(1);
                    t2.j.e(strGroup5, "matcher.group(1)");
                    Locale locale = Locale.US;
                    t2.j.e(locale, "Locale.US");
                    if (strGroup5 == null) {
                        throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
                    }
                    String lowerCase = strGroup5.toLowerCase(locale);
                    t2.j.e(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
                    String strPattern = m.f366k.pattern();
                    t2.j.e(strPattern, "MONTH_PATTERN.pattern()");
                    iJ = z2.g.J(strPattern, lowerCase, 0, false, 6, null) / 4;
                } else if (i5 == -1 && matcher.usePattern(m.f365j).matches()) {
                    String strGroup6 = matcher.group(1);
                    t2.j.e(strGroup6, "matcher.group(1)");
                    i5 = Integer.parseInt(strGroup6);
                }
                iA = a(str, iA2 + 1, i4, false);
            }
            if (70 <= i5 && 99 >= i5) {
                i5 += 1900;
            }
            if (i5 >= 0 && 69 >= i5) {
                i5 += 2000;
            }
            if (!(i5 >= 1601)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            if (!(iJ != -1)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            if (!(1 <= i7 && 31 >= i7)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            if (!(i6 >= 0 && 23 >= i6)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            if (!(i8 >= 0 && 59 >= i8)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            if (!(i9 >= 0 && 59 >= i9)) {
                throw new IllegalArgumentException("Failed requirement.");
            }
            GregorianCalendar gregorianCalendar = new GregorianCalendar(C2.c.f583f);
            gregorianCalendar.setLenient(false);
            gregorianCalendar.set(1, i5);
            gregorianCalendar.set(2, iJ - 1);
            gregorianCalendar.set(5, i7);
            gregorianCalendar.set(11, i6);
            gregorianCalendar.set(12, i8);
            gregorianCalendar.set(13, i9);
            gregorianCalendar.set(14, 0);
            return gregorianCalendar.getTimeInMillis();
        }

        private final long h(String str) {
            try {
                long j3 = Long.parseLong(str);
                if (j3 <= 0) {
                    return Long.MIN_VALUE;
                }
                return j3;
            } catch (NumberFormatException e3) {
                if (new z2.f("-?\\d+").a(str)) {
                    return z2.g.u(str, "-", false, 2, null) ? Long.MIN_VALUE : Long.MAX_VALUE;
                }
                throw e3;
            }
        }

        public final m c(u uVar, String str) {
            t2.j.f(uVar, "url");
            t2.j.f(str, "setCookie");
            return d(System.currentTimeMillis(), uVar, str);
        }

        public final m d(long j3, u uVar, String str) {
            long j4;
            m mVar;
            String str2;
            String str3;
            t2.j.f(uVar, "url");
            t2.j.f(str, "setCookie");
            int iO = C2.c.o(str, ';', 0, 0, 6, null);
            int iO2 = C2.c.o(str, '=', 0, iO, 2, null);
            if (iO2 == iO) {
                return null;
            }
            String strW = C2.c.W(str, 0, iO2, 1, null);
            if (strW.length() == 0 || C2.c.v(strW) != -1) {
                return null;
            }
            String strV = C2.c.V(str, iO2 + 1, iO);
            if (C2.c.v(strV) != -1) {
                return null;
            }
            int i3 = iO + 1;
            int length = str.length();
            String strF = null;
            String str4 = null;
            boolean z3 = false;
            boolean z4 = false;
            boolean z5 = false;
            boolean z6 = true;
            long jH = -1;
            long jG = 253402300799999L;
            while (i3 < length) {
                int iM = C2.c.m(str, ';', i3, length);
                int iM2 = C2.c.m(str, '=', i3, iM);
                String strV2 = C2.c.V(str, i3, iM2);
                String strV3 = iM2 < iM ? C2.c.V(str, iM2 + 1, iM) : "";
                if (z2.g.j(strV2, "expires", true)) {
                    try {
                        jG = g(strV3, 0, strV3.length());
                        z5 = true;
                    } catch (NumberFormatException | IllegalArgumentException unused) {
                    }
                } else if (z2.g.j(strV2, "max-age", true)) {
                    jH = h(strV3);
                    z5 = true;
                } else if (z2.g.j(strV2, "domain", true)) {
                    strF = f(strV3);
                    z6 = false;
                } else if (z2.g.j(strV2, "path", true)) {
                    str4 = strV3;
                } else if (z2.g.j(strV2, "secure", true)) {
                    z3 = true;
                } else if (z2.g.j(strV2, "httponly", true)) {
                    z4 = true;
                }
                i3 = iM + 1;
            }
            long j5 = Long.MIN_VALUE;
            if (jH == Long.MIN_VALUE) {
                j4 = j5;
            } else if (jH != -1) {
                long j6 = j3 + (jH <= 9223372036854775L ? jH * ((long) 1000) : Long.MAX_VALUE);
                if (j6 >= j3) {
                    j5 = 253402300799999L;
                    if (j6 <= 253402300799999L) {
                        j4 = j6;
                    }
                } else {
                    j5 = 253402300799999L;
                }
                j4 = j5;
            } else {
                j4 = jG;
            }
            String strH = uVar.h();
            if (strF == null) {
                str2 = strH;
                mVar = null;
            } else {
                if (!b(strH, strF)) {
                    return null;
                }
                mVar = null;
                str2 = strF;
            }
            if (strH.length() != str2.length() && PublicSuffixDatabase.f9730h.c().c(str2) == null) {
                return mVar;
            }
            String strSubstring = "/";
            String str5 = str4;
            if (str5 == null || !z2.g.u(str5, "/", false, 2, mVar)) {
                String strD = uVar.d();
                int iO3 = z2.g.O(strD, '/', 0, false, 6, null);
                if (iO3 != 0) {
                    if (strD == null) {
                        throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
                    }
                    strSubstring = strD.substring(0, iO3);
                    t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                }
                str3 = strSubstring;
            } else {
                str3 = str5;
            }
            return new m(strW, strV, j4, str2, str3, z3, z4, z5, z6, null);
        }

        public final List e(u uVar, t tVar) {
            t2.j.f(uVar, "url");
            t2.j.f(tVar, "headers");
            List listI = tVar.i("Set-Cookie");
            int size = listI.size();
            ArrayList arrayList = null;
            for (int i3 = 0; i3 < size; i3++) {
                m mVarC = c(uVar, (String) listI.get(i3));
                if (mVarC != null) {
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                    }
                    arrayList.add(mVarC);
                }
            }
            if (arrayList == null) {
                return AbstractC0586n.g();
            }
            List listUnmodifiableList = Collections.unmodifiableList(arrayList);
            t2.j.e(listUnmodifiableList, "Collections.unmodifiableList(cookies)");
            return listUnmodifiableList;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private m(String str, String str2, long j3, String str3, String str4, boolean z3, boolean z4, boolean z5, boolean z6) {
        this.f370a = str;
        this.f371b = str2;
        this.f372c = j3;
        this.f373d = str3;
        this.f374e = str4;
        this.f375f = z3;
        this.f376g = z4;
        this.f377h = z5;
        this.f378i = z6;
    }

    public final String a() {
        return this.f370a;
    }

    public final String b() {
        return this.f371b;
    }

    public boolean equals(Object obj) {
        if (obj instanceof m) {
            m mVar = (m) obj;
            if (t2.j.b(mVar.f370a, this.f370a) && t2.j.b(mVar.f371b, this.f371b) && mVar.f372c == this.f372c && t2.j.b(mVar.f373d, this.f373d) && t2.j.b(mVar.f374e, this.f374e) && mVar.f375f == this.f375f && mVar.f376g == this.f376g && mVar.f377h == this.f377h && mVar.f378i == this.f378i) {
                return true;
            }
        }
        return false;
    }

    public final String g() {
        return this.f370a;
    }

    public final String h(boolean z3) {
        StringBuilder sb = new StringBuilder();
        sb.append(this.f370a);
        sb.append('=');
        sb.append(this.f371b);
        if (this.f377h) {
            if (this.f372c == Long.MIN_VALUE) {
                sb.append("; max-age=0");
            } else {
                sb.append("; expires=");
                sb.append(H2.c.b(new Date(this.f372c)));
            }
        }
        if (!this.f378i) {
            sb.append("; domain=");
            if (z3) {
                sb.append(".");
            }
            sb.append(this.f373d);
        }
        sb.append("; path=");
        sb.append(this.f374e);
        if (this.f375f) {
            sb.append("; secure");
        }
        if (this.f376g) {
            sb.append("; httponly");
        }
        String string = sb.toString();
        t2.j.e(string, "toString()");
        return string;
    }

    public int hashCode() {
        return ((((((((((((((((527 + this.f370a.hashCode()) * 31) + this.f371b.hashCode()) * 31) + Long.hashCode(this.f372c)) * 31) + this.f373d.hashCode()) * 31) + this.f374e.hashCode()) * 31) + Boolean.hashCode(this.f375f)) * 31) + Boolean.hashCode(this.f376g)) * 31) + Boolean.hashCode(this.f377h)) * 31) + Boolean.hashCode(this.f378i);
    }

    public final String i() {
        return this.f371b;
    }

    public String toString() {
        return h(false);
    }

    public /* synthetic */ m(String str, String str2, long j3, String str3, String str4, boolean z3, boolean z4, boolean z5, boolean z6, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, j3, str3, str4, z3, z4, z5, z6);
    }
}
