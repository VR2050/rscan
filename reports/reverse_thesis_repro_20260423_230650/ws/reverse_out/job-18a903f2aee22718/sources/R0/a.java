package R0;

import Q0.i;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends c {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(i iVar, q.e eVar, h hVar) {
        super(iVar, eVar, hVar);
        j.f(iVar, "bitmapPool");
        j.f(eVar, "decodeBuffers");
        j.f(hVar, "platformDecoderOptions");
    }

    @Override // R0.c
    public int d(int i3, int i4, BitmapFactory.Options options) {
        j.f(options, "options");
        Bitmap.Config config = options.inPreferredConfig;
        if (config != null) {
            return Y0.e.i(i3, i4, config);
        }
        throw new IllegalStateException("Required value was null.");
    }
}
