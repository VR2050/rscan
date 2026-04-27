package G0;

import android.net.Uri;
import com.facebook.common.time.RealtimeSinceBootClock;

/* JADX INFO: renamed from: G0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0173b implements R.d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f767a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final H0.g f768b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final H0.h f769c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final H0.d f770d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final R.d f771e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f772f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Object f773g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f774h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final long f775i;

    public C0173b(String str, H0.g gVar, H0.h hVar, H0.d dVar, R.d dVar2, String str2) {
        t2.j.f(str, "sourceString");
        t2.j.f(hVar, "rotationOptions");
        t2.j.f(dVar, "imageDecodeOptions");
        this.f767a = str;
        this.f768b = gVar;
        this.f769c = hVar;
        this.f770d = dVar;
        this.f771e = dVar2;
        this.f772f = str2;
        this.f774h = (((((((((str.hashCode() * 31) + (gVar != null ? gVar.hashCode() : 0)) * 31) + hVar.hashCode()) * 31) + dVar.hashCode()) * 31) + (dVar2 != null ? dVar2.hashCode() : 0)) * 31) + (str2 != null ? str2.hashCode() : 0);
        this.f775i = RealtimeSinceBootClock.get().now();
    }

    @Override // R.d
    public boolean a() {
        return false;
    }

    @Override // R.d
    public boolean b(Uri uri) {
        t2.j.f(uri, "uri");
        String strC = c();
        String string = uri.toString();
        t2.j.e(string, "toString(...)");
        return z2.g.z(strC, string, false, 2, null);
    }

    @Override // R.d
    public String c() {
        return this.f767a;
    }

    public final void d(Object obj) {
        this.f773g = obj;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!t2.j.b(C0173b.class, obj != null ? obj.getClass() : null)) {
            return false;
        }
        t2.j.d(obj, "null cannot be cast to non-null type com.facebook.imagepipeline.cache.BitmapMemoryCacheKey");
        C0173b c0173b = (C0173b) obj;
        return t2.j.b(this.f767a, c0173b.f767a) && t2.j.b(this.f768b, c0173b.f768b) && t2.j.b(this.f769c, c0173b.f769c) && t2.j.b(this.f770d, c0173b.f770d) && t2.j.b(this.f771e, c0173b.f771e) && t2.j.b(this.f772f, c0173b.f772f);
    }

    public int hashCode() {
        return this.f774h;
    }

    public String toString() {
        return "BitmapMemoryCacheKey(sourceString=" + this.f767a + ", resizeOptions=" + this.f768b + ", rotationOptions=" + this.f769c + ", imageDecodeOptions=" + this.f770d + ", postprocessorCacheKey=" + this.f771e + ", postprocessorName=" + this.f772f + ")";
    }
}
