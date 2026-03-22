package p005b.p199l.p200a.p201a.p250p1;

import java.io.BufferedOutputStream;
import java.io.OutputStream;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.w */
/* loaded from: classes.dex */
public final class C2363w extends BufferedOutputStream {

    /* renamed from: c */
    public boolean f6140c;

    public C2363w(OutputStream outputStream) {
        super(outputStream);
    }

    /* renamed from: b */
    public void m2605b(OutputStream outputStream) {
        C4195m.m4771I(this.f6140c);
        ((BufferedOutputStream) this).out = outputStream;
        ((BufferedOutputStream) this).count = 0;
        this.f6140c = false;
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f6140c = true;
        try {
            flush();
            th = null;
        } catch (Throwable th) {
            th = th;
        }
        try {
            ((BufferedOutputStream) this).out.close();
        } catch (Throwable th2) {
            if (th == null) {
                th = th2;
            }
        }
        if (th == null) {
            return;
        }
        int i2 = C2344d0.f6035a;
        throw th;
    }

    public C2363w(OutputStream outputStream, int i2) {
        super(outputStream, i2);
    }
}
