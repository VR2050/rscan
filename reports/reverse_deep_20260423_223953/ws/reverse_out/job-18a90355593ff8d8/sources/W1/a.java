package W1;

import android.content.Context;
import android.net.Uri;
import java.util.Objects;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class a {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final C0045a f2831f = new C0045a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f2832a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final D1.a f2833b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Uri f2834c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final double f2835d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f2836e;

    /* JADX INFO: renamed from: W1.a$a, reason: collision with other inner class name */
    public static final class C0045a {
        public /* synthetic */ C0045a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final a a(Context context) {
            j.f(context, "context");
            return new a(context, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", 0.0d, 0.0d, D1.a.f593b, 12, null);
        }

        private C0045a() {
        }
    }

    public a(Context context, String str, double d3, double d4, D1.a aVar) {
        j.f(context, "context");
        j.f(aVar, "cacheControl");
        this.f2832a = str;
        this.f2833b = aVar;
        this.f2834c = b(context);
        this.f2835d = d3 * d4;
    }

    private final Uri a(Context context) {
        this.f2836e = true;
        return c.f2840b.a().g(context, this.f2832a);
    }

    private final Uri b(Context context) {
        try {
            Uri uri = Uri.parse(this.f2832a);
            return uri.getScheme() == null ? a(context) : uri;
        } catch (NullPointerException unused) {
            return a(context);
        }
    }

    public final D1.a c() {
        return this.f2833b;
    }

    public final double d() {
        return this.f2835d;
    }

    public final String e() {
        return this.f2832a;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !j.b(getClass(), obj.getClass())) {
            return false;
        }
        a aVar = (a) obj;
        return Double.compare(aVar.f2835d, this.f2835d) == 0 && g() == aVar.g() && j.b(f(), aVar.f()) && j.b(this.f2832a, aVar.f2832a) && this.f2833b == aVar.f2833b;
    }

    public Uri f() {
        return this.f2834c;
    }

    public boolean g() {
        return this.f2836e;
    }

    public int hashCode() {
        return Objects.hash(f(), this.f2832a, Double.valueOf(this.f2835d), Boolean.valueOf(g()), this.f2833b);
    }

    public /* synthetic */ a(Context context, String str, double d3, double d4, D1.a aVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, str, (i3 & 4) != 0 ? 0.0d : d3, (i3 & 8) != 0 ? 0.0d : d4, (i3 & 16) != 0 ? D1.a.f593b : aVar);
    }
}
