package G1;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class d {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final a f857e = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final String f858f = d.class.getSimpleName();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f859a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final SharedPreferences f860b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f861c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Map f862d;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public d(Context context) {
        j.f(context, "appContext");
        this.f859a = context;
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
        j.e(defaultSharedPreferences, "getDefaultSharedPreferences(...)");
        this.f860b = defaultSharedPreferences;
        String packageName = context.getPackageName();
        j.e(packageName, "getPackageName(...)");
        this.f861c = packageName;
        this.f862d = new LinkedHashMap();
    }

    public final Map a() {
        return this.f862d;
    }

    public String b() {
        String string = this.f860b.getString("debug_http_host", null);
        if (string != null && string.length() > 0) {
            return string;
        }
        String strH = com.facebook.react.modules.systeminfo.a.h(this.f859a);
        if (j.b(strH, "localhost")) {
            Y.a.I(f858f, "You seem to be running on device. Run '" + com.facebook.react.modules.systeminfo.a.b(this.f859a) + "' to forward the debug server's port to the device.");
        }
        return strH;
    }

    public final String c() {
        return this.f861c;
    }

    public void d(String str) {
        j.f(str, "host");
        this.f860b.edit().putString("debug_http_host", str).apply();
    }
}
