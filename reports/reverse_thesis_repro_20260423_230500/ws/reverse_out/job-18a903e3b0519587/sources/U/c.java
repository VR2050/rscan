package U;

/* JADX INFO: loaded from: classes.dex */
public class c implements b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static c f2799a;

    private c() {
    }

    public static synchronized c b() {
        try {
            if (f2799a == null) {
                f2799a = new c();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f2799a;
    }

    @Override // U.b
    public void a(a aVar) {
    }
}
