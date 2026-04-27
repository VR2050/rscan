package A0;

import android.icu.text.Collator;
import android.icu.text.NumberingSystem;
import android.icu.util.Calendar;
import android.icu.util.ULocale;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public abstract class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static String f26a = "calendar";

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static String f27b = "ca";

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static String f28c = "numbers";

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static String f29d = "nu";

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static String f30e = "hours";

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static String f31f = "hc";

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static String f32g = "collation";

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static String f33h = "co";

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static String f34i = "colnumeric";

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static String f35j = "kn";

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static String f36k = "colcasefirst";

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static String f37l = "kf";

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static HashMap f38m = new a();

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static HashMap f39n = new b();

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final Map f40o = new c();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static Map f41p = new d();

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static Map f42q = new e();

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static Map f43r = new f();

    class a extends HashMap {
        a() {
            put(i.f27b, i.f26a);
            put(i.f29d, i.f28c);
            put(i.f31f, i.f30e);
            put(i.f33h, i.f32g);
            put(i.f35j, i.f34i);
            put(i.f37l, i.f36k);
        }
    }

    class b extends HashMap {
        b() {
            put(i.f26a, i.f27b);
            put(i.f28c, i.f29d);
            put(i.f30e, i.f31f);
            put(i.f32g, i.f33h);
            put(i.f34i, i.f35j);
            put(i.f36k, i.f37l);
        }
    }

    class c extends HashMap {
        c() {
            put("dictionary", "dict");
            put("phonebook", "phonebk");
            put("traditional", "trad");
            put("gb2312han", "gb2312");
        }
    }

    class d extends HashMap {
        d() {
            put("gregorian", "gregory");
        }
    }

    class e extends HashMap {
        e() {
            put("traditional", "traditio");
        }
    }

    class f extends HashMap {
        f() {
            put("nu", new String[]{"adlm", "ahom", "arab", "arabext", "bali", "beng", "bhks", "brah", "cakm", "cham", "deva", "diak", "fullwide", "gong", "gonm", "gujr", "guru", "hanidec", "hmng", "hmnp", "java", "kali", "khmr", "knda", "lana", "lanatham", "laoo", "latn", "lepc", "limb", "mathbold", "mathdbl", "mathmono", "mathsanb", "mathsans", "mlym", "modi", "mong", "mroo", "mtei", "mymr", "mymrshan", "mymrtlng", "newa", "nkoo", "olck", "orya", "osma", "rohg", "saur", "segment", "shrd", "sind", "sinh", "sora", "sund", "takr", "talu", "tamldec", "telu", "thai", "tibt", "tirh", "vaii", "wara", "wcho"});
            put("co", new String[]{"big5han", "compat", "dict", "direct", "ducet", "emoji", "eor", "gb2312", "phonebk", "phonetic", "pinyin", "reformed", "searchjl", "stroke", "trad", "unihan", "zhuyin"});
            put("ca", new String[]{"buddhist", "chinese", "coptic", "dangi", "ethioaa", "ethiopic", "gregory", "hebrew", "indian", "islamic", "islamic-umalqura", "islamic-tbla", "islamic-civil", "islamic-rgsa", "iso8601", "japanese", "persian", "roc"});
        }
    }

    public static String a(String str) {
        return f38m.containsKey(str) ? (String) f38m.get(str) : str;
    }

    public static String b(String str) {
        return f39n.containsKey(str) ? (String) f39n.get(str) : str;
    }

    public static boolean c(String str, String str2, A0.b bVar) {
        ULocale uLocale = (ULocale) bVar.h();
        String[] availableNames = new String[0];
        if (str.equals("co")) {
            if (str2.equals("standard") || str2.equals("search")) {
                return false;
            }
            availableNames = Collator.getKeywordValuesForLocale("co", uLocale, false);
        } else if (str.equals("ca")) {
            availableNames = Calendar.getKeywordValuesForLocale("ca", uLocale, false);
        } else if (str.equals("nu")) {
            availableNames = NumberingSystem.getAvailableNames();
        }
        if (availableNames.length == 0) {
            return true;
        }
        return Arrays.asList(availableNames).contains(str2);
    }

    public static String d(String str) {
        return !f41p.containsKey(str) ? str : (String) f41p.get(str);
    }

    public static String e(String str) {
        Map map = f40o;
        return !map.containsKey(str) ? str : (String) map.get(str);
    }

    public static Object f(String str, Object obj) {
        return (str.equals("ca") && A0.d.m(obj)) ? d((String) obj) : (str.equals("nu") && A0.d.m(obj)) ? g((String) obj) : (str.equals("co") && A0.d.m(obj)) ? e((String) obj) : (str.equals("kn") && A0.d.m(obj) && obj.equals("yes")) ? A0.d.r("true") : ((str.equals("kn") || str.equals("kf")) && A0.d.m(obj) && obj.equals("no")) ? A0.d.r("false") : obj;
    }

    public static String g(String str) {
        return !f42q.containsKey(str) ? str : (String) f42q.get(str);
    }
}
