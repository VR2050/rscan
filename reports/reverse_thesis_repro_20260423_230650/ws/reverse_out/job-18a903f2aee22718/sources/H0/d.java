package H0;

import X.i;
import android.graphics.Bitmap;
import android.graphics.ColorSpace;

/* JADX INFO: loaded from: classes.dex */
public class d {

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final d f989m = b().a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f990a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f991b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final boolean f992c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final boolean f993d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public final boolean f994e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public final boolean f995f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public final boolean f996g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public final Bitmap.Config f997h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public final Bitmap.Config f998i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public final L0.c f999j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public final ColorSpace f1000k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f1001l;

    public d(e eVar) {
        this.f990a = eVar.l();
        this.f991b = eVar.k();
        this.f992c = eVar.h();
        this.f993d = eVar.n();
        this.f994e = eVar.m();
        this.f995f = eVar.g();
        this.f996g = eVar.j();
        this.f997h = eVar.c();
        this.f998i = eVar.b();
        this.f999j = eVar.f();
        eVar.d();
        this.f1000k = eVar.e();
        this.f1001l = eVar.i();
    }

    public static d a() {
        return f989m;
    }

    public static e b() {
        return new e();
    }

    protected i.a c() {
        return X.i.b(this).a("minDecodeIntervalMs", this.f990a).a("maxDimensionPx", this.f991b).c("decodePreviewFrame", this.f992c).c("useLastFrameForPreview", this.f993d).c("useEncodedImageForPreview", this.f994e).c("decodeAllFrames", this.f995f).c("forceStaticImage", this.f996g).b("bitmapConfigName", this.f997h.name()).b("animatedBitmapConfigName", this.f998i.name()).b("customImageDecoder", this.f999j).b("bitmapTransformation", null).b("colorSpace", this.f1000k);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        d dVar = (d) obj;
        if (this.f990a != dVar.f990a || this.f991b != dVar.f991b || this.f992c != dVar.f992c || this.f993d != dVar.f993d || this.f994e != dVar.f994e || this.f995f != dVar.f995f || this.f996g != dVar.f996g) {
            return false;
        }
        boolean z3 = this.f1001l;
        if (z3 || this.f997h == dVar.f997h) {
            return (z3 || this.f998i == dVar.f998i) && this.f999j == dVar.f999j && this.f1000k == dVar.f1000k;
        }
        return false;
    }

    public int hashCode() {
        int iOrdinal = (((((((((((this.f990a * 31) + this.f991b) * 31) + (this.f992c ? 1 : 0)) * 31) + (this.f993d ? 1 : 0)) * 31) + (this.f994e ? 1 : 0)) * 31) + (this.f995f ? 1 : 0)) * 31) + (this.f996g ? 1 : 0);
        if (!this.f1001l) {
            iOrdinal = (iOrdinal * 31) + this.f997h.ordinal();
        }
        if (!this.f1001l) {
            int i3 = iOrdinal * 31;
            Bitmap.Config config = this.f998i;
            iOrdinal = i3 + (config != null ? config.ordinal() : 0);
        }
        int i4 = iOrdinal * 31;
        L0.c cVar = this.f999j;
        int iHashCode = (i4 + (cVar != null ? cVar.hashCode() : 0)) * 961;
        ColorSpace colorSpace = this.f1000k;
        return iHashCode + (colorSpace != null ? colorSpace.hashCode() : 0);
    }

    public String toString() {
        return "ImageDecodeOptions{" + c().toString() + "}";
    }
}
