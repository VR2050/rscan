package W1;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import androidx.core.content.res.f;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2840b = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final c f2841c = new c();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f2842a = new HashMap();

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final c a() {
            return c.f2841c;
        }

        private a() {
        }
    }

    private c() {
    }

    private final int b(Context context, String str) {
        int identifier = context.getResources().getIdentifier(str, "drawable", context.getPackageName());
        this.f2842a.put(str, Integer.valueOf(identifier));
        return identifier;
    }

    public static final c d() {
        return f2840b.a();
    }

    public final synchronized void c() {
        this.f2842a.clear();
    }

    public final Drawable e(Context context, String str) {
        j.f(context, "context");
        int iF = f(context, str);
        if (iF > 0) {
            return f.e(context.getResources(), iF, null);
        }
        return null;
    }

    public final int f(Context context, String str) {
        j.f(context, "context");
        if (str == null || str.length() == 0) {
            return 0;
        }
        String lowerCase = str.toLowerCase(Locale.ROOT);
        j.e(lowerCase, "toLowerCase(...)");
        String strQ = g.q(lowerCase, "-", "_", false, 4, null);
        try {
            return Integer.parseInt(strQ);
        } catch (NumberFormatException unused) {
            synchronized (this) {
                try {
                    Integer num = (Integer) this.f2842a.get(strQ);
                    return num != null ? num.intValue() : b(context, strQ);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public final Uri g(Context context, String str) {
        j.f(context, "context");
        int iF = f(context, str);
        if (iF > 0) {
            Uri uriBuild = new Uri.Builder().scheme("res").path(String.valueOf(iF)).build();
            j.c(uriBuild);
            return uriBuild;
        }
        Uri uri = Uri.EMPTY;
        j.c(uri);
        return uri;
    }
}
