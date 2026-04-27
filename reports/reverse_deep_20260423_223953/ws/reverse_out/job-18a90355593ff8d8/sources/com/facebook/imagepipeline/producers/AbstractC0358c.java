package com.facebook.imagepipeline.producers;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0358c implements InterfaceC0369n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f6246a = false;

    public static boolean e(int i3) {
        return (i3 & 1) == 1;
    }

    public static boolean f(int i3) {
        return !e(i3);
    }

    public static int l(boolean z3) {
        return z3 ? 1 : 0;
    }

    public static boolean m(int i3, int i4) {
        return (i3 & i4) != 0;
    }

    public static boolean n(int i3, int i4) {
        return (i3 & i4) == i4;
    }

    public static int o(int i3, int i4) {
        return i3 & (~i4);
    }

    @Override // com.facebook.imagepipeline.producers.InterfaceC0369n
    public synchronized void a(Throwable th) {
        if (this.f6246a) {
            return;
        }
        this.f6246a = true;
        try {
            h(th);
        } catch (Exception e3) {
            k(e3);
        }
    }

    @Override // com.facebook.imagepipeline.producers.InterfaceC0369n
    public synchronized void b() {
        if (this.f6246a) {
            return;
        }
        this.f6246a = true;
        try {
            g();
        } catch (Exception e3) {
            k(e3);
        }
    }

    @Override // com.facebook.imagepipeline.producers.InterfaceC0369n
    public synchronized void c(float f3) {
        if (this.f6246a) {
            return;
        }
        try {
            j(f3);
        } catch (Exception e3) {
            k(e3);
        }
    }

    @Override // com.facebook.imagepipeline.producers.InterfaceC0369n
    public synchronized void d(Object obj, int i3) {
        if (this.f6246a) {
            return;
        }
        this.f6246a = e(i3);
        try {
            i(obj, i3);
        } catch (Exception e3) {
            k(e3);
        }
    }

    protected abstract void g();

    protected abstract void h(Throwable th);

    protected abstract void i(Object obj, int i3);

    protected abstract void j(float f3);

    protected void k(Exception exc) {
        Y.a.M(getClass(), "unhandled exception", exc);
    }
}
