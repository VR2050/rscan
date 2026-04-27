package N0;

import android.graphics.Bitmap;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public interface e extends c {
    static e F(Bitmap bitmap, b0.g gVar, o oVar, int i3, int i4) {
        return b.w0() ? new b(bitmap, gVar, oVar, i3, i4) : new h(bitmap, gVar, oVar, i3, i4);
    }

    static e T(Bitmap bitmap, b0.g gVar, o oVar, int i3) {
        return F(bitmap, gVar, oVar, i3, 0);
    }

    static e a0(AbstractC0311a abstractC0311a, o oVar, int i3, int i4) {
        return b.w0() ? new b(abstractC0311a, oVar, i3, i4) : new h(abstractC0311a, oVar, i3, i4);
    }

    int N();

    int s0();
}
