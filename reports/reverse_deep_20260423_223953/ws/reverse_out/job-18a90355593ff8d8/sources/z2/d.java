package z2;

import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final d f10543a = new d();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final Charset f10544b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final Charset f10545c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final Charset f10546d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final Charset f10547e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final Charset f10548f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final Charset f10549g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static volatile Charset f10550h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static volatile Charset f10551i;

    static {
        Charset charsetForName = Charset.forName("UTF-8");
        t2.j.e(charsetForName, "forName(...)");
        f10544b = charsetForName;
        Charset charsetForName2 = Charset.forName("UTF-16");
        t2.j.e(charsetForName2, "forName(...)");
        f10545c = charsetForName2;
        Charset charsetForName3 = Charset.forName("UTF-16BE");
        t2.j.e(charsetForName3, "forName(...)");
        f10546d = charsetForName3;
        Charset charsetForName4 = Charset.forName("UTF-16LE");
        t2.j.e(charsetForName4, "forName(...)");
        f10547e = charsetForName4;
        Charset charsetForName5 = Charset.forName("US-ASCII");
        t2.j.e(charsetForName5, "forName(...)");
        f10548f = charsetForName5;
        Charset charsetForName6 = Charset.forName("ISO-8859-1");
        t2.j.e(charsetForName6, "forName(...)");
        f10549g = charsetForName6;
    }

    private d() {
    }

    public final Charset a() {
        Charset charset = f10551i;
        if (charset != null) {
            return charset;
        }
        Charset charsetForName = Charset.forName("UTF-32BE");
        t2.j.e(charsetForName, "forName(...)");
        f10551i = charsetForName;
        return charsetForName;
    }

    public final Charset b() {
        Charset charset = f10550h;
        if (charset != null) {
            return charset;
        }
        Charset charsetForName = Charset.forName("UTF-32LE");
        t2.j.e(charsetForName, "forName(...)");
        f10550h = charsetForName;
        return charsetForName;
    }
}
