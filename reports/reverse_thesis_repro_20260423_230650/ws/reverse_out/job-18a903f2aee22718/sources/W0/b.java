package W0;

import android.graphics.Bitmap;
import b0.AbstractC0311a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b f2830a = new b();

    private b() {
    }

    public static final boolean a(a aVar, AbstractC0311a abstractC0311a) {
        if (aVar == null || abstractC0311a == null) {
            return false;
        }
        Object objP = abstractC0311a.P();
        j.e(objP, "get(...)");
        Bitmap bitmap = (Bitmap) objP;
        if (aVar.a()) {
            bitmap.setHasAlpha(true);
        }
        aVar.b(bitmap);
        return true;
    }
}
