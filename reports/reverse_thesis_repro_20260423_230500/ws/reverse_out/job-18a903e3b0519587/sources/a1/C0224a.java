package a1;

/* JADX INFO: renamed from: a1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0224a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0224a f2928a = new C0224a();

    private C0224a() {
    }

    public static final int a(int i3, Object obj) {
        return (i3 * 31) + (obj != null ? obj.hashCode() : 0);
    }
}
