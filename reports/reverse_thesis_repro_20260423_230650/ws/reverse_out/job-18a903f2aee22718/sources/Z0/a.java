package Z0;

/* JADX INFO: loaded from: classes.dex */
public abstract class a {
    public static void a(boolean z3) {
        if (!z3) {
            throw new AssertionError();
        }
    }

    public static void b(boolean z3, String str) {
        if (!z3) {
            throw new AssertionError(str);
        }
    }

    public static Object c(Object obj) {
        if (obj != null) {
            return obj;
        }
        throw new AssertionError();
    }

    public static Object d(Object obj, String str) {
        if (obj != null) {
            return obj;
        }
        throw new AssertionError(str);
    }

    public static Object e(Object obj) {
        return obj;
    }

    public static Object f(Object obj, String str) {
        return obj;
    }
}
