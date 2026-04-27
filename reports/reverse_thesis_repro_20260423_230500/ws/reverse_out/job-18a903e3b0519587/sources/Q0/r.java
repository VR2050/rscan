package Q0;

import android.graphics.Bitmap;

/* JADX INFO: loaded from: classes.dex */
public final class r implements i {
    @Override // a0.InterfaceC0220f
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public Bitmap get(int i3) {
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(1, (int) Math.ceil(((double) i3) / 2.0d), Bitmap.Config.RGB_565);
        t2.j.e(bitmapCreateBitmap, "createBitmap(...)");
        return bitmapCreateBitmap;
    }

    @Override // a0.InterfaceC0220f, b0.g
    /* JADX INFO: renamed from: g, reason: merged with bridge method [inline-methods] */
    public void a(Bitmap bitmap) {
        t2.j.f(bitmap, "value");
        bitmap.recycle();
    }
}
