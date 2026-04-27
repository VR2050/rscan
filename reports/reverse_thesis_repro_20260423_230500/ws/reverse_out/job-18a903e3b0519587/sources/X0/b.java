package X0;

import L0.c;
import N0.d;
import N0.i;
import N0.o;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import f0.f;
import i2.AbstractC0586n;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class b implements c {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f2856c = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Resources f2857a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f2858b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public b(Resources resources) {
        j.f(resources, "resources");
        this.f2857a = resources;
        this.f2858b = new ConcurrentHashMap();
    }

    private final int b(String str) {
        Map map = this.f2858b;
        Object objValueOf = map.get(str);
        if (objValueOf == null) {
            Uri uri = Uri.parse(str);
            j.e(uri, "parse(...)");
            objValueOf = Integer.valueOf(c(uri));
            map.put(str, objValueOf);
        }
        return ((Number) objValueOf).intValue();
    }

    private final int c(Uri uri) {
        Integer numF;
        if (!f.m(uri) && !f.o(uri)) {
            throw new IllegalStateException(("Unsupported uri " + uri).toString());
        }
        List<String> pathSegments = uri.getPathSegments();
        j.e(pathSegments, "getPathSegments(...)");
        String str = (String) AbstractC0586n.L(pathSegments);
        if (str != null && (numF = g.f(str)) != null) {
            return numF.intValue();
        }
        throw new IllegalStateException(("Unable to read resource ID from " + uri.getPath()).toString());
    }

    @Override // L0.c
    public d a(N0.j jVar, int i3, o oVar, H0.d dVar) {
        j.f(jVar, "encodedImage");
        j.f(oVar, "qualityInfo");
        j.f(dVar, "options");
        try {
            String strE0 = jVar.e0();
            if (strE0 == null) {
                throw new IllegalStateException("No source in encoded image");
            }
            Drawable drawableE = androidx.core.content.res.f.e(this.f2857a, b(strE0), null);
            if (drawableE != null) {
                return new i(drawableE);
            }
            return null;
        } catch (Throwable th) {
            Y.a.n("XmlFormatDecoder", "Cannot decode xml", th);
            return null;
        }
    }
}
