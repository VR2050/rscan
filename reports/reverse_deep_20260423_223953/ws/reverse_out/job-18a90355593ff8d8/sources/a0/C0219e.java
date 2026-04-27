package a0;

/* JADX INFO: renamed from: a0.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0219e implements InterfaceC0218d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static C0219e f2916a;

    public static synchronized C0219e b() {
        try {
            if (f2916a == null) {
                f2916a = new C0219e();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f2916a;
    }

    @Override // a0.InterfaceC0218d
    public void a(InterfaceC0217c interfaceC0217c) {
    }
}
