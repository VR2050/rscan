package N0;

import android.graphics.Bitmap;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
class h extends b {
    protected h(AbstractC0311a abstractC0311a, o oVar, int i3, int i4) {
        super(abstractC0311a, oVar, i3, i4);
    }

    protected void finalize() throws Throwable {
        if (a()) {
            return;
        }
        Y.a.K("DefaultCloseableStaticBitmap", "finalize: %s %x still open.", getClass().getSimpleName(), Integer.valueOf(System.identityHashCode(this)));
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    protected h(Bitmap bitmap, b0.g gVar, o oVar, int i3, int i4) {
        super(bitmap, gVar, oVar, i3, i4);
    }
}
