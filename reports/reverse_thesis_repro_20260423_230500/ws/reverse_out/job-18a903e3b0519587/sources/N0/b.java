package N0;

import android.graphics.Bitmap;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class b extends a implements e {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static boolean f1875j = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private AbstractC0311a f1876e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private volatile Bitmap f1877f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final o f1878g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f1879h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f1880i;

    protected b(Bitmap bitmap, b0.g gVar, o oVar, int i3, int i4) {
        this.f1877f = (Bitmap) X.k.g(bitmap);
        this.f1876e = AbstractC0311a.n0(this.f1877f, (b0.g) X.k.g(gVar));
        this.f1878g = oVar;
        this.f1879h = i3;
        this.f1880i = i4;
    }

    private synchronized AbstractC0311a t0() {
        AbstractC0311a abstractC0311a;
        abstractC0311a = this.f1876e;
        this.f1876e = null;
        this.f1877f = null;
        return abstractC0311a;
    }

    private static int u0(Bitmap bitmap) {
        if (bitmap == null) {
            return 0;
        }
        return bitmap.getHeight();
    }

    private static int v0(Bitmap bitmap) {
        if (bitmap == null) {
            return 0;
        }
        return bitmap.getWidth();
    }

    public static boolean w0() {
        return f1875j;
    }

    @Override // N0.c
    public Bitmap C() {
        return this.f1877f;
    }

    @Override // N0.e
    public int N() {
        return this.f1879h;
    }

    @Override // N0.d
    public synchronized boolean a() {
        return this.f1876e == null;
    }

    @Override // N0.d
    public int b0() {
        return Y0.e.j(this.f1877f);
    }

    @Override // N0.d, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        AbstractC0311a abstractC0311aT0 = t0();
        if (abstractC0311aT0 != null) {
            abstractC0311aT0.close();
        }
    }

    @Override // N0.d, N0.l
    public int d() {
        int i3;
        return (this.f1879h % 180 != 0 || (i3 = this.f1880i) == 5 || i3 == 7) ? v0(this.f1877f) : u0(this.f1877f);
    }

    @Override // N0.d, N0.l
    public int h() {
        int i3;
        return (this.f1879h % 180 != 0 || (i3 = this.f1880i) == 5 || i3 == 7) ? u0(this.f1877f) : v0(this.f1877f);
    }

    @Override // N0.a, N0.d
    public o k() {
        return this.f1878g;
    }

    @Override // N0.e
    public int s0() {
        return this.f1880i;
    }

    protected b(AbstractC0311a abstractC0311a, o oVar, int i3, int i4) {
        AbstractC0311a abstractC0311a2 = (AbstractC0311a) X.k.g(abstractC0311a.y());
        this.f1876e = abstractC0311a2;
        this.f1877f = (Bitmap) abstractC0311a2.P();
        this.f1878g = oVar;
        this.f1879h = i3;
        this.f1880i = i4;
    }
}
