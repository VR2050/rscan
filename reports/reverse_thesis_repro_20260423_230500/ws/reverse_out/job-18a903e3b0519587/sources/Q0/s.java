package Q0;

import android.graphics.Bitmap;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public final class s implements i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f2387a;

    public s() {
        Set setB = X.m.b();
        t2.j.e(setB, "newIdentityHashSet(...)");
        this.f2387a = setB;
    }

    @Override // a0.InterfaceC0220f
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public Bitmap get(int i3) {
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(1, (int) Math.ceil(((double) i3) / 2.0d), Bitmap.Config.RGB_565);
        t2.j.e(bitmapCreateBitmap, "createBitmap(...)");
        this.f2387a.add(bitmapCreateBitmap);
        return bitmapCreateBitmap;
    }

    @Override // a0.InterfaceC0220f, b0.g
    /* JADX INFO: renamed from: g, reason: merged with bridge method [inline-methods] */
    public void a(Bitmap bitmap) {
        t2.j.f(bitmap, "value");
        this.f2387a.remove(bitmap);
        bitmap.recycle();
    }
}
