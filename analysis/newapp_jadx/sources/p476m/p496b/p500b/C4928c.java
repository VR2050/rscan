package p476m.p496b.p500b;

import android.database.SQLException;

/* renamed from: m.b.b.c */
/* loaded from: classes3.dex */
public class C4928c extends SQLException {
    private static final long serialVersionUID = -5877937327907457779L;

    public C4928c(String str) {
        super(str);
    }

    public C4928c(String str, Throwable th) {
        super(str);
        try {
            initCause(th);
        } catch (Throwable unused) {
        }
    }
}
