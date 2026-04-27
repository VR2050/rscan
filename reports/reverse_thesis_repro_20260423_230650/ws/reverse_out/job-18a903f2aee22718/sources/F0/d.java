package F0;

import android.graphics.Bitmap;
import b0.g;

/* JADX INFO: loaded from: classes.dex */
public class d implements g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static d f737a;

    private d() {
    }

    public static d b() {
        if (f737a == null) {
            f737a = new d();
        }
        return f737a;
    }

    @Override // b0.g
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public void a(Bitmap bitmap) {
        bitmap.recycle();
    }
}
