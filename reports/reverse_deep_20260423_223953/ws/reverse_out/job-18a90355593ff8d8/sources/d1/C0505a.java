package d1;

/* JADX INFO: renamed from: d1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0505a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0505a f9151a = new C0505a();

    private C0505a() {
    }

    public static final boolean a() {
        return false;
    }

    public static final Class b(String str) {
        t2.j.f(str, "className");
        if (a()) {
            return Class.forName(str);
        }
        return null;
    }
}
