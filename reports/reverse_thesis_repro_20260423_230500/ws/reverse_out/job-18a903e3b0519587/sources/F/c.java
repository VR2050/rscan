package F;

import android.os.Bundle;
import androidx.lifecycle.f;
import androidx.savedstate.Recreator;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f730d = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d f731a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final androidx.savedstate.a f732b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f733c;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final c a(d dVar) {
            j.f(dVar, "owner");
            return new c(dVar, null);
        }

        private a() {
        }
    }

    public /* synthetic */ c(d dVar, DefaultConstructorMarker defaultConstructorMarker) {
        this(dVar);
    }

    public static final c a(d dVar) {
        return f730d.a(dVar);
    }

    public final androidx.savedstate.a b() {
        return this.f732b;
    }

    public final void c() {
        f fVarS = this.f731a.s();
        if (fVarS.b() != f.b.INITIALIZED) {
            throw new IllegalStateException("Restarter must be created only during owner's initialization stage");
        }
        fVarS.a(new Recreator(this.f731a));
        this.f732b.e(fVarS);
        this.f733c = true;
    }

    public final void d(Bundle bundle) {
        if (!this.f733c) {
            c();
        }
        f fVarS = this.f731a.s();
        if (!fVarS.b().b(f.b.STARTED)) {
            this.f732b.f(bundle);
            return;
        }
        throw new IllegalStateException(("performRestore cannot be called when owner is " + fVarS.b()).toString());
    }

    public final void e(Bundle bundle) {
        j.f(bundle, "outBundle");
        this.f732b.g(bundle);
    }

    private c(d dVar) {
        this.f731a = dVar;
        this.f732b = new androidx.savedstate.a();
    }
}
