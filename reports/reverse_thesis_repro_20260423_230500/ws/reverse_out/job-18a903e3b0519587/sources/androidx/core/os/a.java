package androidx.core.os;

import android.os.Build;
import android.os.ext.SdkExtensions;
import java.util.Locale;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f4358a = new a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final int f4359b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final int f4360c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final int f4361d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final int f4362e;

    /* JADX INFO: renamed from: androidx.core.os.a$a, reason: collision with other inner class name */
    private static final class C0061a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final C0061a f4363a = new C0061a();

        private C0061a() {
        }

        public final int a(int i3) {
            return SdkExtensions.getExtensionVersion(i3);
        }
    }

    static {
        int i3 = Build.VERSION.SDK_INT;
        f4359b = i3 >= 30 ? C0061a.f4363a.a(30) : 0;
        f4360c = i3 >= 30 ? C0061a.f4363a.a(31) : 0;
        f4361d = i3 >= 30 ? C0061a.f4363a.a(33) : 0;
        f4362e = i3 >= 30 ? C0061a.f4363a.a(1000000) : 0;
    }

    private a() {
    }

    public static final boolean a(String str, String str2) {
        j.f(str, "codename");
        j.f(str2, "buildCodename");
        if (j.b("REL", str2)) {
            return false;
        }
        Locale locale = Locale.ROOT;
        String upperCase = str2.toUpperCase(locale);
        j.e(upperCase, "this as java.lang.String).toUpperCase(Locale.ROOT)");
        String upperCase2 = str.toUpperCase(locale);
        j.e(upperCase2, "this as java.lang.String).toUpperCase(Locale.ROOT)");
        return upperCase.compareTo(upperCase2) >= 0;
    }

    public static final boolean b() {
        int i3 = Build.VERSION.SDK_INT;
        if (i3 < 33) {
            if (i3 >= 32) {
                String str = Build.VERSION.CODENAME;
                j.e(str, "CODENAME");
                if (a("Tiramisu", str)) {
                }
            }
            return false;
        }
        return true;
    }
}
