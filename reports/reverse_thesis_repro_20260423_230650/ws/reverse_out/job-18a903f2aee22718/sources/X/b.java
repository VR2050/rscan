package X;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/* JADX INFO: loaded from: classes.dex */
public abstract class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    static final Logger f2843a = Logger.getLogger(b.class.getName());

    public static void a(Closeable closeable, boolean z3) throws IOException {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException e3) {
            if (!z3) {
                throw e3;
            }
            f2843a.log(Level.WARNING, "IOException thrown while closing Closeable.", (Throwable) e3);
        }
    }

    public static void b(InputStream inputStream) {
        try {
            a(inputStream, true);
        } catch (IOException e3) {
            throw new AssertionError(e3);
        }
    }
}
