package t2;

/* JADX INFO: loaded from: classes.dex */
public abstract class u {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final v f10217a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final x2.b[] f10218b;

    static {
        v vVar = null;
        try {
            vVar = (v) Class.forName("kotlin.reflect.jvm.internal.ReflectionFactoryImpl").newInstance();
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException | InstantiationException unused) {
        }
        if (vVar == null) {
            vVar = new v();
        }
        f10217a = vVar;
        f10218b = new x2.b[0];
    }

    public static x2.d a(h hVar) {
        return f10217a.a(hVar);
    }

    public static x2.b b(Class cls) {
        return f10217a.b(cls);
    }

    public static x2.c c(Class cls) {
        return f10217a.c(cls, "");
    }

    public static x2.e d(l lVar) {
        return f10217a.d(lVar);
    }

    public static String e(k kVar) {
        return f10217a.f(kVar);
    }
}
