package b0;

import X.k;
import android.graphics.Bitmap;
import java.io.Closeable;
import java.io.IOException;

/* JADX INFO: renamed from: b0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0311a implements Cloneable, Closeable {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static int f5390g;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected boolean f5393b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected final h f5394c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected final c f5395d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected final Throwable f5396e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static Class f5389f = AbstractC0311a.class;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final g f5391h = new C0085a();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final c f5392i = new b();

    /* JADX INFO: renamed from: b0.a$a, reason: collision with other inner class name */
    class C0085a implements g {
        C0085a() {
        }

        @Override // b0.g
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(Closeable closeable) {
            try {
                X.b.a(closeable, true);
            } catch (IOException unused) {
            }
        }
    }

    /* JADX INFO: renamed from: b0.a$b */
    class b implements c {
        b() {
        }

        @Override // b0.AbstractC0311a.c
        public boolean a() {
            return false;
        }

        @Override // b0.AbstractC0311a.c
        public void b(h hVar, Throwable th) {
            Object objF = hVar.f();
            Y.a.G(AbstractC0311a.f5389f, "Finalized without closing: %x %x (type = %s)", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(hVar)), objF == null ? null : objF.getClass().getName());
        }
    }

    /* JADX INFO: renamed from: b0.a$c */
    public interface c {
        boolean a();

        void b(h hVar, Throwable th);
    }

    protected AbstractC0311a(h hVar, c cVar, Throwable th) {
        this.f5394c = (h) k.g(hVar);
        hVar.b();
        this.f5395d = cVar;
        this.f5396e = th;
    }

    public static AbstractC0311a A(AbstractC0311a abstractC0311a) {
        if (abstractC0311a != null) {
            return abstractC0311a.y();
        }
        return null;
    }

    public static void D(AbstractC0311a abstractC0311a) {
        if (abstractC0311a != null) {
            abstractC0311a.close();
        }
    }

    public static boolean d0(AbstractC0311a abstractC0311a) {
        return abstractC0311a != null && abstractC0311a.Z();
    }

    public static AbstractC0311a e0(Closeable closeable) {
        return n0(closeable, f5391h);
    }

    public static AbstractC0311a f0(Closeable closeable, c cVar) {
        if (closeable == null) {
            return null;
        }
        return u0(closeable, f5391h, cVar, cVar.a() ? new Throwable() : null);
    }

    public static AbstractC0311a n0(Object obj, g gVar) {
        return t0(obj, gVar, f5392i);
    }

    public static AbstractC0311a t0(Object obj, g gVar, c cVar) {
        if (obj == null) {
            return null;
        }
        return u0(obj, gVar, cVar, cVar.a() ? new Throwable() : null);
    }

    public static AbstractC0311a u0(Object obj, g gVar, c cVar, Throwable th) {
        if (obj == null) {
            return null;
        }
        if ((obj instanceof Bitmap) || (obj instanceof d)) {
            int i3 = f5390g;
            if (i3 == 1) {
                return new b0.c(obj, gVar, cVar, th);
            }
            if (i3 == 2) {
                return new f(obj, gVar, cVar, th);
            }
            if (i3 == 3) {
                return new e(obj);
            }
        }
        return new b0.b(obj, gVar, cVar, th);
    }

    public synchronized Object P() {
        k.i(!this.f5393b);
        return k.g(this.f5394c.f());
    }

    public int W() {
        if (Z()) {
            return System.identityHashCode(this.f5394c.f());
        }
        return 0;
    }

    public synchronized boolean Z() {
        return !this.f5393b;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        synchronized (this) {
            try {
                if (this.f5393b) {
                    return;
                }
                this.f5393b = true;
                this.f5394c.d();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX INFO: renamed from: x */
    public abstract AbstractC0311a clone();

    public synchronized AbstractC0311a y() {
        if (!Z()) {
            return null;
        }
        return clone();
    }

    protected AbstractC0311a(Object obj, g gVar, c cVar, Throwable th, boolean z3) {
        this.f5394c = new h(obj, gVar, z3);
        this.f5395d = cVar;
        this.f5396e = th;
    }
}
