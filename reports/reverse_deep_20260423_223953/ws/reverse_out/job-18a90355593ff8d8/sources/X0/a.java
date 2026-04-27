package X0;

import N0.d;
import N0.f;
import android.graphics.drawable.Drawable;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a implements M0.a {
    @Override // M0.a
    public boolean a(d dVar) {
        j.f(dVar, "image");
        return dVar instanceof f;
    }

    @Override // M0.a
    public Drawable b(d dVar) {
        j.f(dVar, "image");
        f fVar = dVar instanceof f ? (f) dVar : null;
        if (fVar != null) {
            return fVar.g0();
        }
        return null;
    }
}
