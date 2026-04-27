package Q0;

import a0.InterfaceC0218d;
import android.graphics.Bitmap;

/* JADX INFO: loaded from: classes.dex */
public class u implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected final B f2388a = new j();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2389b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f2390c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final G f2391d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f2392e;

    public u(int i3, int i4, G g3, InterfaceC0218d interfaceC0218d) {
        this.f2389b = i3;
        this.f2390c = i4;
        this.f2391d = g3;
        if (interfaceC0218d != null) {
            interfaceC0218d.a(this);
        }
    }

    private Bitmap f(int i3) {
        this.f2391d.a(i3);
        return Bitmap.createBitmap(1, i3, Bitmap.Config.ALPHA_8);
    }

    private synchronized void i(int i3) {
        Bitmap bitmap;
        while (this.f2392e > i3 && (bitmap = (Bitmap) this.f2388a.b()) != null) {
            int iA = this.f2388a.a(bitmap);
            this.f2392e -= iA;
            this.f2391d.c(iA);
        }
    }

    @Override // a0.InterfaceC0220f
    /* JADX INFO: renamed from: g, reason: merged with bridge method [inline-methods] */
    public synchronized Bitmap get(int i3) {
        try {
            int i4 = this.f2392e;
            int i5 = this.f2389b;
            if (i4 > i5) {
                i(i5);
            }
            Bitmap bitmap = (Bitmap) this.f2388a.get(i3);
            if (bitmap == null) {
                return f(i3);
            }
            int iA = this.f2388a.a(bitmap);
            this.f2392e -= iA;
            this.f2391d.b(iA);
            return bitmap;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // a0.InterfaceC0220f, b0.g
    /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
    public void a(Bitmap bitmap) {
        int iA = this.f2388a.a(bitmap);
        if (iA <= this.f2390c) {
            this.f2391d.e(iA);
            this.f2388a.c(bitmap);
            synchronized (this) {
                this.f2392e += iA;
            }
        }
    }
}
