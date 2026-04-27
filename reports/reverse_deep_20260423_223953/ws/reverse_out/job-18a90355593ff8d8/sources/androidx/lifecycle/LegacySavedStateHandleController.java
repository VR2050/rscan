package androidx.lifecycle;

import androidx.lifecycle.LegacySavedStateHandleController;
import androidx.lifecycle.f;
import androidx.savedstate.a;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public final class LegacySavedStateHandleController {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final LegacySavedStateHandleController f5098a = new LegacySavedStateHandleController();

    public static final class a implements a.InterfaceC0081a {
        @Override // androidx.savedstate.a.InterfaceC0081a
        public void a(F.d dVar) {
            t2.j.f(dVar, "owner");
            if (!(dVar instanceof C)) {
                throw new IllegalStateException("Internal error: OnRecreation should be registered only on components that implement ViewModelStoreOwner");
            }
            B bR = ((C) dVar).r();
            androidx.savedstate.a aVarB = dVar.b();
            Iterator it = bR.c().iterator();
            while (it.hasNext()) {
                y yVarB = bR.b((String) it.next());
                t2.j.c(yVarB);
                LegacySavedStateHandleController.a(yVarB, aVarB, dVar.s());
            }
            if (bR.c().isEmpty()) {
                return;
            }
            aVarB.i(a.class);
        }
    }

    private LegacySavedStateHandleController() {
    }

    public static final void a(y yVar, androidx.savedstate.a aVar, f fVar) {
        t2.j.f(yVar, "viewModel");
        t2.j.f(aVar, "registry");
        t2.j.f(fVar, "lifecycle");
        SavedStateHandleController savedStateHandleController = (SavedStateHandleController) yVar.c("androidx.lifecycle.savedstate.vm.tag");
        if (savedStateHandleController == null || savedStateHandleController.i()) {
            return;
        }
        savedStateHandleController.h(aVar, fVar);
        f5098a.b(aVar, fVar);
    }

    private final void b(final androidx.savedstate.a aVar, final f fVar) {
        f.b bVarB = fVar.b();
        if (bVarB == f.b.INITIALIZED || bVarB.b(f.b.STARTED)) {
            aVar.i(a.class);
        } else {
            fVar.a(new i() { // from class: androidx.lifecycle.LegacySavedStateHandleController$tryToAddRecreator$1
                @Override // androidx.lifecycle.i
                public void d(k kVar, f.a aVar2) {
                    t2.j.f(kVar, "source");
                    t2.j.f(aVar2, "event");
                    if (aVar2 == f.a.ON_START) {
                        fVar.c(this);
                        aVar.i(LegacySavedStateHandleController.a.class);
                    }
                }
            });
        }
    }
}
