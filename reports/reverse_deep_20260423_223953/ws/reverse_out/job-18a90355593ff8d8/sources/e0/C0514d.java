package e0;

/* JADX INFO: renamed from: e0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0514d implements InterfaceC0511a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final C0514d f9177a = new C0514d();

    private C0514d() {
    }

    public static C0514d a() {
        return f9177a;
    }

    @Override // e0.InterfaceC0511a
    public long now() {
        return System.currentTimeMillis();
    }
}
