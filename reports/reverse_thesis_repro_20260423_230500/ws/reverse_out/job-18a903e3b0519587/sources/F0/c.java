package F0;

import I0.C0176a;
import Q0.E;
import Q0.i;
import R0.f;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final c f736a = new c();

    private c() {
    }

    public static final b a(E e3, f fVar, C0176a c0176a) {
        j.f(e3, "poolFactory");
        j.f(fVar, "platformDecoder");
        j.f(c0176a, "closeableReferenceFactory");
        i iVarB = e3.b();
        j.e(iVarB, "getBitmapPool(...)");
        return new a(iVarB, c0176a);
    }
}
