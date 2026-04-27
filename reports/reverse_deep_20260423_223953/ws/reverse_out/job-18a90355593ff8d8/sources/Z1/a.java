package Z1;

/* JADX INFO: loaded from: classes.dex */
public abstract class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static b f2910a;

    public static void a(b bVar) {
        synchronized (a.class) {
            try {
                if (f2910a != null) {
                    throw new IllegalStateException("Cannot re-initialize NativeLoader.");
                }
                f2910a = bVar;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static void b(b bVar) {
        if (c()) {
            return;
        }
        a(bVar);
    }

    public static boolean c() {
        boolean z3;
        synchronized (a.class) {
            z3 = f2910a != null;
        }
        return z3;
    }

    public static boolean d(String str) {
        return e(str, 0);
    }

    public static boolean e(String str, int i3) {
        b bVar;
        synchronized (a.class) {
            bVar = f2910a;
            if (bVar == null) {
                throw new IllegalStateException("NativeLoader has not been initialized.  To use standard native library loading, call NativeLoader.init(new SystemDelegate()).");
            }
        }
        return bVar.a(str, i3);
    }
}
