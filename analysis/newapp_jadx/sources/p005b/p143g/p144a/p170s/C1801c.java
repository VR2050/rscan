package p005b.p143g.p144a.p170s;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Queue;

/* renamed from: b.g.a.s.c */
/* loaded from: classes.dex */
public class C1801c extends InputStream {

    /* renamed from: c */
    public static final Queue<C1801c> f2752c;

    /* renamed from: e */
    public InputStream f2753e;

    /* renamed from: f */
    public IOException f2754f;

    static {
        char[] cArr = C1807i.f2767a;
        f2752c = new ArrayDeque(0);
    }

    @Override // java.io.InputStream
    public int available() {
        return this.f2753e.available();
    }

    /* renamed from: b */
    public void m1137b() {
        this.f2754f = null;
        this.f2753e = null;
        Queue<C1801c> queue = f2752c;
        synchronized (queue) {
            queue.offer(this);
        }
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f2753e.close();
    }

    @Override // java.io.InputStream
    public void mark(int i2) {
        this.f2753e.mark(i2);
    }

    @Override // java.io.InputStream
    public boolean markSupported() {
        return this.f2753e.markSupported();
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) {
        try {
            return this.f2753e.read(bArr);
        } catch (IOException e2) {
            this.f2754f = e2;
            return -1;
        }
    }

    @Override // java.io.InputStream
    public synchronized void reset() {
        this.f2753e.reset();
    }

    @Override // java.io.InputStream
    public long skip(long j2) {
        try {
            return this.f2753e.skip(j2);
        } catch (IOException e2) {
            this.f2754f = e2;
            return 0L;
        }
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i2, int i3) {
        try {
            return this.f2753e.read(bArr, i2, i3);
        } catch (IOException e2) {
            this.f2754f = e2;
            return -1;
        }
    }

    @Override // java.io.InputStream
    public int read() {
        try {
            return this.f2753e.read();
        } catch (IOException e2) {
            this.f2754f = e2;
            return -1;
        }
    }
}
