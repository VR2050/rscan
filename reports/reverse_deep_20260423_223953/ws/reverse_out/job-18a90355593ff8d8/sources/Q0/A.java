package Q0;

/* JADX INFO: loaded from: classes.dex */
public class A implements G {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static A f2315a;

    private A() {
    }

    public static synchronized A h() {
        try {
            if (f2315a == null) {
                f2315a = new A();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f2315a;
    }

    @Override // Q0.G
    public void d() {
    }

    @Override // Q0.G
    public void g() {
    }

    @Override // Q0.G
    public void a(int i3) {
    }

    @Override // Q0.G
    public void b(int i3) {
    }

    @Override // Q0.G
    public void c(int i3) {
    }

    @Override // Q0.G
    public void e(int i3) {
    }

    @Override // Q0.G
    public void f(com.facebook.imagepipeline.memory.a aVar) {
    }
}
