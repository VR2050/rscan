package B2;

import java.nio.charset.Charset;

/* JADX INFO: loaded from: classes.dex */
public final class o {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final o f390a = new o();

    private o() {
    }

    public static final String a(String str, String str2, Charset charset) {
        t2.j.f(str, "username");
        t2.j.f(str2, "password");
        t2.j.f(charset, "charset");
        return "Basic " + Q2.l.f2556f.d(str + ':' + str2, charset).a();
    }
}
