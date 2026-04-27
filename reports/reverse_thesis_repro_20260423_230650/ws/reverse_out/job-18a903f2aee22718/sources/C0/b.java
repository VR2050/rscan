package C0;

import i2.AbstractC0586n;
import java.util.List;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b f548a = new b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final c f549b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final c f550c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final c f551d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final c f552e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final c f553f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final c f554g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final c f555h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final c f556i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final c f557j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final c f558k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final c f559l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final c f560m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final c f561n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final c f562o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    public static final List f563p;

    static {
        c cVar = new c("JPEG", "jpeg");
        f549b = cVar;
        c cVar2 = new c("PNG", "png");
        f550c = cVar2;
        c cVar3 = new c("GIF", "gif");
        f551d = cVar3;
        c cVar4 = new c("BMP", "bmp");
        f552e = cVar4;
        c cVar5 = new c("ICO", "ico");
        f553f = cVar5;
        c cVar6 = new c("WEBP_SIMPLE", "webp");
        f554g = cVar6;
        c cVar7 = new c("WEBP_LOSSLESS", "webp");
        f555h = cVar7;
        c cVar8 = new c("WEBP_EXTENDED", "webp");
        f556i = cVar8;
        c cVar9 = new c("WEBP_EXTENDED_WITH_ALPHA", "webp");
        f557j = cVar9;
        c cVar10 = new c("WEBP_ANIMATED", "webp");
        f558k = cVar10;
        c cVar11 = new c("HEIF", "heif");
        f559l = cVar11;
        f560m = new c("DNG", "dng");
        c cVar12 = new c("BINARY_XML", "xml");
        f561n = cVar12;
        c cVar13 = new c("AVIF", "avif");
        f562o = cVar13;
        f563p = AbstractC0586n.i(cVar, cVar2, cVar3, cVar4, cVar5, cVar6, cVar7, cVar8, cVar9, cVar10, cVar11, cVar12, cVar13);
    }

    private b() {
    }

    public static final boolean a(c cVar) {
        j.f(cVar, "imageFormat");
        return cVar == f554g || cVar == f555h || cVar == f556i || cVar == f557j;
    }

    public static final boolean b(c cVar) {
        j.f(cVar, "imageFormat");
        return a(cVar) || cVar == f558k;
    }
}
