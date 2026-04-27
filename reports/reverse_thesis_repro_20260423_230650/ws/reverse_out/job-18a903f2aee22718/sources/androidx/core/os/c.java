package androidx.core.os;

import android.os.LocaleList;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final c f4368b = a(new Locale[0]);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d f4369a;

    static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private static final Locale[] f4370a = {new Locale("en", "XA"), new Locale("ar", "XB")};

        static Locale a(String str) {
            return Locale.forLanguageTag(str);
        }

        private static boolean b(Locale locale) {
            for (Locale locale2 : f4370a) {
                if (locale2.equals(locale)) {
                    return true;
                }
            }
            return false;
        }

        static boolean c(Locale locale, Locale locale2) {
            if (locale.equals(locale2)) {
                return true;
            }
            if (!locale.getLanguage().equals(locale2.getLanguage()) || b(locale) || b(locale2)) {
                return false;
            }
            String strA = androidx.core.text.a.a(locale);
            if (!strA.isEmpty()) {
                return strA.equals(androidx.core.text.a.a(locale2));
            }
            String country = locale.getCountry();
            return country.isEmpty() || country.equals(locale2.getCountry());
        }
    }

    static class b {
        static LocaleList a(Locale... localeArr) {
            return new LocaleList(localeArr);
        }

        static LocaleList b() {
            return LocaleList.getAdjustedDefault();
        }

        static LocaleList c() {
            return LocaleList.getDefault();
        }
    }

    private c(d dVar) {
        this.f4369a = dVar;
    }

    public static c a(Locale... localeArr) {
        return h(b.a(localeArr));
    }

    public static c b(String str) {
        if (str == null || str.isEmpty()) {
            return d();
        }
        String[] strArrSplit = str.split(",", -1);
        int length = strArrSplit.length;
        Locale[] localeArr = new Locale[length];
        for (int i3 = 0; i3 < length; i3++) {
            localeArr[i3] = a.a(strArrSplit[i3]);
        }
        return a(localeArr);
    }

    public static c d() {
        return f4368b;
    }

    public static c h(LocaleList localeList) {
        return new c(new e(localeList));
    }

    public Locale c(int i3) {
        return this.f4369a.get(i3);
    }

    public boolean e() {
        return this.f4369a.isEmpty();
    }

    public boolean equals(Object obj) {
        return (obj instanceof c) && this.f4369a.equals(((c) obj).f4369a);
    }

    public int f() {
        return this.f4369a.size();
    }

    public String g() {
        return this.f4369a.a();
    }

    public int hashCode() {
        return this.f4369a.hashCode();
    }

    public String toString() {
        return this.f4369a.toString();
    }
}
