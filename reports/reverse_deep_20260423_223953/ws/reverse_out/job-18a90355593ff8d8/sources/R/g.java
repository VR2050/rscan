package R;

import R.a;

/* JADX INFO: loaded from: classes.dex */
public class g implements a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static g f2617a;

    private g() {
    }

    public static synchronized g b() {
        try {
            if (f2617a == null) {
                f2617a = new g();
            }
        } catch (Throwable th) {
            throw th;
        }
        return f2617a;
    }

    @Override // R.a
    public void a(a.EnumC0038a enumC0038a, Class cls, String str, Throwable th) {
    }
}
