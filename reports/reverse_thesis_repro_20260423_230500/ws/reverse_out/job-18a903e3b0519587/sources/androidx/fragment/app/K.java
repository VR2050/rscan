package androidx.fragment.app;

import android.util.Log;
import java.io.Writer;

/* JADX INFO: loaded from: classes.dex */
final class K extends Writer {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f4866b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private StringBuilder f4867c = new StringBuilder(128);

    K(String str) {
        this.f4866b = str;
    }

    private void b() {
        if (this.f4867c.length() > 0) {
            Log.d(this.f4866b, this.f4867c.toString());
            StringBuilder sb = this.f4867c;
            sb.delete(0, sb.length());
        }
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        b();
    }

    @Override // java.io.Writer, java.io.Flushable
    public void flush() {
        b();
    }

    @Override // java.io.Writer
    public void write(char[] cArr, int i3, int i4) {
        for (int i5 = 0; i5 < i4; i5++) {
            char c3 = cArr[i3 + i5];
            if (c3 == '\n') {
                b();
            } else {
                this.f4867c.append(c3);
            }
        }
    }
}
