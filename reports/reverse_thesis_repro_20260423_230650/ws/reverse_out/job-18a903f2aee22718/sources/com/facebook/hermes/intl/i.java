package com.facebook.hermes.intl;

import android.icu.text.DateFormat;
import android.icu.text.NumberingSystem;
import android.icu.text.SimpleDateFormat;
import android.icu.util.Calendar;
import android.icu.util.TimeZone;
import android.icu.util.ULocale;
import com.facebook.hermes.intl.b;
import java.text.AttributedCharacterIterator;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/* JADX INFO: loaded from: classes.dex */
public class i implements com.facebook.hermes.intl.b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private DateFormat f6033a = null;

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f6034a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        static final /* synthetic */ int[] f6035b;

        static {
            int[] iArr = new int[b.k.values().length];
            f6035b = iArr;
            try {
                iArr[b.k.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f6035b[b.k.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f6035b[b.k.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f6035b[b.k.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f6035b[b.k.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            int[] iArr2 = new int[b.EnumC0093b.values().length];
            f6034a = iArr2;
            try {
                iArr2[b.EnumC0093b.FULL.ordinal()] = 1;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f6034a[b.EnumC0093b.LONG.ordinal()] = 2;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f6034a[b.EnumC0093b.MEDIUM.ordinal()] = 3;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f6034a[b.EnumC0093b.SHORT.ordinal()] = 4;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f6034a[b.EnumC0093b.UNDEFINED.ordinal()] = 5;
            } catch (NoSuchFieldError unused10) {
            }
        }
    }

    private static class b {
        public static String a(String str) {
            StringBuilder sb = new StringBuilder();
            boolean z3 = false;
            for (int i3 = 0; i3 < str.length(); i3++) {
                char cCharAt = str.charAt(i3);
                if (cCharAt == '\'') {
                    z3 = !z3;
                } else if (!z3 && ((cCharAt >= 'A' && cCharAt <= 'Z') || (cCharAt >= 'a' && cCharAt <= 'z'))) {
                    sb.append(str.charAt(i3));
                }
            }
            return sb.toString();
        }
    }

    i() {
    }

    private static String i(A0.b bVar, b.EnumC0093b enumC0093b, b.k kVar) {
        return enumC0093b == b.EnumC0093b.UNDEFINED ? ((SimpleDateFormat) DateFormat.getTimeInstance(m(kVar), (ULocale) bVar.h())).toLocalizedPattern() : kVar == b.k.UNDEFINED ? ((SimpleDateFormat) DateFormat.getDateInstance(l(enumC0093b), (ULocale) bVar.h())).toLocalizedPattern() : ((SimpleDateFormat) DateFormat.getDateTimeInstance(l(enumC0093b), m(kVar), (ULocale) bVar.h())).toLocalizedPattern();
    }

    private static String j(A0.b bVar, b.m mVar, b.d dVar, b.n nVar, b.i iVar, b.c cVar, b.f fVar, b.h hVar, b.j jVar, b.l lVar, b.g gVar, b.EnumC0093b enumC0093b, b.k kVar, Object obj) {
        StringBuilder sb = new StringBuilder();
        if (enumC0093b == b.EnumC0093b.UNDEFINED && kVar == b.k.UNDEFINED) {
            sb.append(mVar.b());
            sb.append(dVar.b());
            sb.append(nVar.b());
            sb.append(iVar.b());
            sb.append(cVar.b());
            if (gVar == b.g.H11 || gVar == b.g.H12) {
                sb.append(fVar.b());
            } else {
                sb.append(fVar.c());
            }
            sb.append(hVar.b());
            sb.append(jVar.b());
            sb.append(lVar.b());
        } else {
            sb.append(i(bVar, enumC0093b, kVar));
            HashMap mapB = bVar.b();
            if (mapB.containsKey("hc")) {
                String str = (String) mapB.get("hc");
                if (str == "h11" || str == "h12") {
                    k(sb, new char[]{'H', 'K', 'k'}, 'h');
                } else if (str == "h23" || str == "h24") {
                    k(sb, new char[]{'h', 'H', 'K'}, 'k');
                }
            }
            if (gVar == b.g.H11 || gVar == b.g.H12) {
                k(sb, new char[]{'H', 'K', 'k'}, 'h');
            } else if (gVar == b.g.H23 || gVar == b.g.H24) {
                k(sb, new char[]{'h', 'H', 'K'}, 'k');
            }
            if (!A0.d.n(obj) && !A0.d.j(obj)) {
                if (A0.d.e(obj)) {
                    k(sb, new char[]{'H', 'K', 'k'}, 'h');
                } else {
                    k(sb, new char[]{'h', 'H', 'K'}, 'k');
                }
            }
        }
        return sb.toString();
    }

    private static void k(StringBuilder sb, char[] cArr, char c3) {
        for (int i3 = 0; i3 < sb.length(); i3++) {
            int length = cArr.length;
            int i4 = 0;
            while (true) {
                if (i4 < length) {
                    if (sb.charAt(i3) == cArr[i4]) {
                        sb.setCharAt(i3, c3);
                        break;
                    }
                    i4++;
                }
            }
        }
    }

    static int l(b.EnumC0093b enumC0093b) throws A0.e {
        int i3 = a.f6034a[enumC0093b.ordinal()];
        if (i3 == 1) {
            return 0;
        }
        if (i3 == 2) {
            return 1;
        }
        if (i3 == 3) {
            return 2;
        }
        if (i3 == 4) {
            return 3;
        }
        throw new A0.e("Invalid DateStyle: " + enumC0093b.toString());
    }

    static int m(b.k kVar) throws A0.e {
        int i3 = a.f6035b[kVar.ordinal()];
        if (i3 == 1) {
            return 0;
        }
        if (i3 == 2) {
            return 1;
        }
        if (i3 == 3) {
            return 2;
        }
        if (i3 == 4) {
            return 3;
        }
        throw new A0.e("Invalid DateStyle: " + kVar.toString());
    }

    @Override // com.facebook.hermes.intl.b
    public AttributedCharacterIterator a(double d3) {
        return this.f6033a.formatToCharacterIterator(Double.valueOf(d3));
    }

    @Override // com.facebook.hermes.intl.b
    public String b(double d3) {
        return this.f6033a.format(new Date((long) d3));
    }

    @Override // com.facebook.hermes.intl.b
    public String c(A0.b bVar) {
        return NumberingSystem.getInstance((ULocale) bVar.h()).getName();
    }

    @Override // com.facebook.hermes.intl.b
    public b.g d(A0.b bVar) {
        try {
            String strA = b.a(((SimpleDateFormat) DateFormat.getTimeInstance(0, (ULocale) bVar.h())).toPattern());
            return strA.contains(String.valueOf('h')) ? b.g.H12 : strA.contains(String.valueOf('K')) ? b.g.H11 : strA.contains(String.valueOf('H')) ? b.g.H23 : b.g.H24;
        } catch (ClassCastException unused) {
            return b.g.H24;
        }
    }

    @Override // com.facebook.hermes.intl.b
    public String e(A0.b bVar) {
        return A0.i.d(DateFormat.getDateInstance(3, (ULocale) bVar.h()).getCalendar().getType());
    }

    @Override // com.facebook.hermes.intl.b
    public String f(AttributedCharacterIterator.Attribute attribute, String str) {
        if (attribute == DateFormat.Field.DAY_OF_WEEK) {
            return "weekday";
        }
        if (attribute == DateFormat.Field.ERA) {
            return "era";
        }
        if (attribute != DateFormat.Field.YEAR) {
            return attribute == DateFormat.Field.MONTH ? "month" : attribute == DateFormat.Field.DAY_OF_MONTH ? "day" : (attribute == DateFormat.Field.HOUR0 || attribute == DateFormat.Field.HOUR1 || attribute == DateFormat.Field.HOUR_OF_DAY0 || attribute == DateFormat.Field.HOUR_OF_DAY1) ? "hour" : attribute == DateFormat.Field.MINUTE ? "minute" : attribute == DateFormat.Field.SECOND ? "second" : attribute == DateFormat.Field.TIME_ZONE ? "timeZoneName" : attribute == DateFormat.Field.AM_PM ? "dayPeriod" : attribute.toString().equals("android.icu.text.DateFormat$Field(related year)") ? "relatedYear" : "literal";
        }
        try {
            Double.parseDouble(str);
            return "year";
        } catch (NumberFormatException unused) {
            return "yearName";
        }
    }

    @Override // com.facebook.hermes.intl.b
    public void g(A0.b bVar, String str, String str2, b.e eVar, b.m mVar, b.d dVar, b.n nVar, b.i iVar, b.c cVar, b.f fVar, b.h hVar, b.j jVar, b.l lVar, b.g gVar, Object obj, b.EnumC0093b enumC0093b, b.k kVar, Object obj2) throws A0.e {
        Calendar calendar;
        String strJ = j(bVar, mVar, dVar, nVar, iVar, cVar, fVar, hVar, jVar, lVar, gVar, enumC0093b, kVar, obj2);
        if (str.isEmpty()) {
            calendar = null;
        } else {
            ArrayList arrayList = new ArrayList();
            arrayList.add(A0.d.h(str));
            A0.b bVarE = bVar.e();
            bVarE.g("ca", arrayList);
            calendar = Calendar.getInstance((ULocale) bVarE.h());
        }
        if (!str2.isEmpty()) {
            try {
                if (NumberingSystem.getInstanceByName(A0.d.h(str2)) == null) {
                    throw new A0.e("Invalid numbering system: " + str2);
                }
                ArrayList arrayList2 = new ArrayList();
                arrayList2.add(A0.d.h(str2));
                bVar.g("nu", arrayList2);
            } catch (RuntimeException unused) {
                throw new A0.e("Invalid numbering system: " + str2);
            }
        }
        if (calendar != null) {
            this.f6033a = DateFormat.getPatternInstance(calendar, strJ, (ULocale) bVar.h());
        } else {
            this.f6033a = DateFormat.getPatternInstance(strJ, (ULocale) bVar.h());
        }
        if (A0.d.n(obj) || A0.d.j(obj)) {
            return;
        }
        this.f6033a.setTimeZone(TimeZone.getTimeZone(A0.d.h(obj)));
    }

    @Override // com.facebook.hermes.intl.b
    public String h(A0.b bVar) {
        return Calendar.getInstance((ULocale) bVar.h()).getTimeZone().getID();
    }
}
