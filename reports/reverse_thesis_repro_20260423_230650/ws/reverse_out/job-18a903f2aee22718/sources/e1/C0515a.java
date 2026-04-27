package e1;

import android.content.res.AssetManager;
import android.graphics.Typeface;
import android.os.Build;
import android.util.SparseArray;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: renamed from: e1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0515a {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final b f9178c = new b(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final String[] f9179d = {"", "_bold", "_italic", "_bold_italic"};

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final String[] f9180e = {".ttf", ".otf"};

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final C0515a f9181f = new C0515a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f9182a = new LinkedHashMap();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f9183b = new LinkedHashMap();

    /* JADX INFO: renamed from: e1.a$a, reason: collision with other inner class name */
    private static final class C0125a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final SparseArray f9184a = new SparseArray(4);

        public final Typeface a(int i3) {
            return (Typeface) this.f9184a.get(i3);
        }

        public final void b(int i3, Typeface typeface) {
            this.f9184a.put(i3, typeface);
        }
    }

    /* JADX INFO: renamed from: e1.a$b */
    public static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Typeface b(String str, int i3, AssetManager assetManager) {
            if (assetManager != null) {
                String str2 = C0515a.f9179d[i3];
                for (String str3 : C0515a.f9180e) {
                    try {
                        Typeface typefaceCreateFromAsset = Typeface.createFromAsset(assetManager, "fonts/" + str + str2 + str3);
                        j.e(typefaceCreateFromAsset, "createFromAsset(...)");
                        return typefaceCreateFromAsset;
                    } catch (RuntimeException unused) {
                    }
                }
            }
            Typeface typefaceCreate = Typeface.create(str, i3);
            j.e(typefaceCreate, "create(...)");
            return typefaceCreate;
        }

        public final C0515a c() {
            return C0515a.f9181f;
        }

        private b() {
        }
    }

    /* JADX INFO: renamed from: e1.a$c */
    public static final class c {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final C0126a f9185c = new C0126a(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final boolean f9186a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f9187b;

        /* JADX INFO: renamed from: e1.a$c$a, reason: collision with other inner class name */
        public static final class C0126a {
            public /* synthetic */ C0126a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private C0126a() {
            }
        }

        public c(int i3, int i4) {
            i3 = i3 == -1 ? 0 : i3;
            this.f9186a = (i3 & 2) != 0;
            this.f9187b = i4 == -1 ? (i3 & 1) != 0 ? 700 : 400 : i4;
        }

        public final Typeface a(Typeface typeface) {
            if (Build.VERSION.SDK_INT < 28) {
                Typeface typefaceCreate = Typeface.create(typeface, b());
                j.c(typefaceCreate);
                return typefaceCreate;
            }
            Typeface typefaceCreate2 = Typeface.create(typeface, this.f9187b, this.f9186a);
            j.c(typefaceCreate2);
            return typefaceCreate2;
        }

        public final int b() {
            return this.f9187b < 700 ? this.f9186a ? 2 : 0 : this.f9186a ? 3 : 1;
        }
    }

    public final Typeface d(String str, c cVar, AssetManager assetManager) {
        j.f(str, "fontFamilyName");
        j.f(cVar, "typefaceStyle");
        if (this.f9183b.containsKey(str)) {
            return cVar.a((Typeface) this.f9183b.get(str));
        }
        Map map = this.f9182a;
        Object c0125a = map.get(str);
        if (c0125a == null) {
            c0125a = new C0125a();
            map.put(str, c0125a);
        }
        C0125a c0125a2 = (C0125a) c0125a;
        int iB = cVar.b();
        Typeface typefaceA = c0125a2.a(iB);
        if (typefaceA != null) {
            return typefaceA;
        }
        Typeface typefaceB = f9178c.b(str, iB, assetManager);
        c0125a2.b(iB, typefaceB);
        return typefaceB;
    }
}
