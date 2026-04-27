package a0;

import X.p;
import java.io.IOException;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
public abstract class k extends OutputStream {
    public abstract InterfaceC0222h b();

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        try {
            super.close();
        } catch (IOException e3) {
            p.a(e3);
        }
    }

    public abstract int size();
}
