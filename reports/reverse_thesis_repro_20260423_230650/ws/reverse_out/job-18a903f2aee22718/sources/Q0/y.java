package Q0;

import a0.InterfaceC0222h;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class y implements InterfaceC0222h {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2396b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    AbstractC0311a f2397c;

    public y(AbstractC0311a abstractC0311a, int i3) {
        X.k.g(abstractC0311a);
        X.k.b(Boolean.valueOf(i3 >= 0 && i3 <= ((w) abstractC0311a.P()).i()));
        this.f2397c = abstractC0311a.clone();
        this.f2396b = i3;
    }

    @Override // a0.InterfaceC0222h
    public synchronized boolean a() {
        return !AbstractC0311a.d0(this.f2397c);
    }

    synchronized void b() {
        if (a()) {
            throw new InterfaceC0222h.a();
        }
    }

    @Override // a0.InterfaceC0222h
    public synchronized int c(int i3, byte[] bArr, int i4, int i5) {
        b();
        X.k.b(Boolean.valueOf(i3 + i5 <= this.f2396b));
        X.k.g(this.f2397c);
        return ((w) this.f2397c.P()).c(i3, bArr, i4, i5);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        AbstractC0311a.D(this.f2397c);
        this.f2397c = null;
    }

    @Override // a0.InterfaceC0222h
    public synchronized byte g(int i3) {
        b();
        X.k.b(Boolean.valueOf(i3 >= 0));
        X.k.b(Boolean.valueOf(i3 < this.f2396b));
        X.k.g(this.f2397c);
        return ((w) this.f2397c.P()).g(i3);
    }

    @Override // a0.InterfaceC0222h
    public synchronized int size() {
        b();
        return this.f2396b;
    }
}
