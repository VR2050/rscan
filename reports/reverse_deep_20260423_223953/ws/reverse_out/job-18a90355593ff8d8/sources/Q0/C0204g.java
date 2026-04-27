package Q0;

import android.graphics.Bitmap;

/* JADX INFO: renamed from: Q0.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0204g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f2360a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f2361b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f2362c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f2363d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final b0.g f2364e;

    /* JADX INFO: renamed from: Q0.g$a */
    class a implements b0.g {
        a() {
        }

        @Override // b0.g
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(Bitmap bitmap) {
            try {
                C0204g.this.a(bitmap);
            } finally {
                bitmap.recycle();
            }
        }
    }

    public C0204g(int i3, int i4) {
        X.k.b(Boolean.valueOf(i3 > 0));
        X.k.b(Boolean.valueOf(i4 > 0));
        this.f2362c = i3;
        this.f2363d = i4;
        this.f2364e = new a();
    }

    public synchronized void a(Bitmap bitmap) {
        int iJ = Y0.e.j(bitmap);
        X.k.c(this.f2360a > 0, "No bitmaps registered.");
        long j3 = iJ;
        X.k.d(j3 <= this.f2361b, "Bitmap size bigger than the total registered size: %d, %d", Integer.valueOf(iJ), Long.valueOf(this.f2361b));
        this.f2361b -= j3;
        this.f2360a--;
    }

    public synchronized int b() {
        return this.f2360a;
    }

    public synchronized int c() {
        return this.f2362c;
    }

    public synchronized int d() {
        return this.f2363d;
    }

    public b0.g e() {
        return this.f2364e;
    }

    public synchronized long f() {
        return this.f2361b;
    }

    public synchronized boolean g(Bitmap bitmap) {
        int iJ = Y0.e.j(bitmap);
        int i3 = this.f2360a;
        if (i3 < this.f2362c) {
            long j3 = this.f2361b;
            long j4 = iJ;
            if (j3 + j4 <= this.f2363d) {
                this.f2360a = i3 + 1;
                this.f2361b = j3 + j4;
                return true;
            }
        }
        return false;
    }
}
