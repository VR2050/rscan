package l0;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;

/* JADX INFO: renamed from: l0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0613a implements M0.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Resources f9480a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final M0.a f9481b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final M0.a f9482c;

    public C0613a(Resources resources, M0.a aVar, M0.a aVar2) {
        this.f9480a = resources;
        this.f9481b = aVar;
        this.f9482c = aVar2;
    }

    private static boolean c(N0.e eVar) {
        return (eVar.s0() == 1 || eVar.s0() == 0) ? false : true;
    }

    private static boolean d(N0.e eVar) {
        return (eVar.N() == 0 || eVar.N() == -1) ? false : true;
    }

    @Override // M0.a
    public boolean a(N0.d dVar) {
        return true;
    }

    @Override // M0.a
    public Drawable b(N0.d dVar) {
        try {
            if (U0.b.d()) {
                U0.b.a("DefaultDrawableFactory#createDrawable");
            }
            if (dVar instanceof N0.e) {
                N0.e eVar = (N0.e) dVar;
                BitmapDrawable bitmapDrawable = new BitmapDrawable(this.f9480a, eVar.C());
                if (!d(eVar) && !c(eVar)) {
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    return bitmapDrawable;
                }
                s0.h hVar = new s0.h(bitmapDrawable, eVar.N(), eVar.s0());
                if (U0.b.d()) {
                    U0.b.b();
                }
                return hVar;
            }
            M0.a aVar = this.f9481b;
            if (aVar != null && aVar.a(dVar)) {
                Drawable drawableB = this.f9481b.b(dVar);
                if (U0.b.d()) {
                    U0.b.b();
                }
                return drawableB;
            }
            M0.a aVar2 = this.f9482c;
            if (aVar2 == null || !aVar2.a(dVar)) {
                if (!U0.b.d()) {
                    return null;
                }
                U0.b.b();
                return null;
            }
            Drawable drawableB2 = this.f9482c.b(dVar);
            if (U0.b.d()) {
                U0.b.b();
            }
            return drawableB2;
        } catch (Throwable th) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th;
        }
    }
}
