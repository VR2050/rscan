package androidx.lifecycle;

import E.a;
import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
public abstract class v {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a.b f5173a = new b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a.b f5174b = new c();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a.b f5175c = new a();

    public static final class a implements a.b {
        a() {
        }
    }

    public static final class b implements a.b {
        b() {
        }
    }

    public static final class c implements a.b {
        c() {
        }
    }

    static final class d extends t2.k implements s2.l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final d f5176c = new d();

        d() {
            super(1);
        }

        @Override // s2.l
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final x d(E.a aVar) {
            t2.j.f(aVar, "$this$initializer");
            return new x();
        }
    }

    public static final void a(F.d dVar) {
        t2.j.f(dVar, "<this>");
        f.b bVarB = dVar.s().b();
        if (bVarB != f.b.INITIALIZED && bVarB != f.b.CREATED) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (dVar.b().c("androidx.lifecycle.internal.SavedStateHandlesProvider") == null) {
            w wVar = new w(dVar.b(), (C) dVar);
            dVar.b().h("androidx.lifecycle.internal.SavedStateHandlesProvider", wVar);
            dVar.s().a(new SavedStateHandleAttacher(wVar));
        }
    }

    public static final x b(C c3) {
        t2.j.f(c3, "<this>");
        E.c cVar = new E.c();
        cVar.a(t2.u.b(x.class), d.f5176c);
        return (x) new z(c3, cVar.b()).b("androidx.lifecycle.internal.SavedStateHandlesVM", x.class);
    }
}
