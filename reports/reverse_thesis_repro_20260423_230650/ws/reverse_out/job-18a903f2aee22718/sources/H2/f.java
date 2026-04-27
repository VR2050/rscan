package H2;

/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final f f1078a = new f();

    private f() {
    }

    public static final boolean b(String str) {
        t2.j.f(str, "method");
        return (t2.j.b(str, "GET") || t2.j.b(str, "HEAD")) ? false : true;
    }

    public static final boolean e(String str) {
        t2.j.f(str, "method");
        return t2.j.b(str, "POST") || t2.j.b(str, "PUT") || t2.j.b(str, "PATCH") || t2.j.b(str, "PROPPATCH") || t2.j.b(str, "REPORT");
    }

    public final boolean a(String str) {
        t2.j.f(str, "method");
        return t2.j.b(str, "POST") || t2.j.b(str, "PATCH") || t2.j.b(str, "PUT") || t2.j.b(str, "DELETE") || t2.j.b(str, "MOVE");
    }

    public final boolean c(String str) {
        t2.j.f(str, "method");
        return !t2.j.b(str, "PROPFIND");
    }

    public final boolean d(String str) {
        t2.j.f(str, "method");
        return t2.j.b(str, "PROPFIND");
    }
}
