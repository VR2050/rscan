package androidx.savedstate;

import F.d;
import android.os.Bundle;
import androidx.lifecycle.f;
import androidx.lifecycle.i;
import androidx.lifecycle.k;
import androidx.savedstate.Recreator;
import java.util.Map;
import k.b;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final b f5269g = new b(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f5271b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Bundle f5272c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f5273d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Recreator.b f5274e;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final k.b f5270a = new k.b();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f5275f = true;

    /* JADX INFO: renamed from: androidx.savedstate.a$a, reason: collision with other inner class name */
    public interface InterfaceC0081a {
        void a(d dVar);
    }

    private static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private b() {
        }
    }

    public interface c {
        Bundle a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void d(a aVar, k kVar, f.a aVar2) {
        j.f(aVar, "this$0");
        j.f(kVar, "<anonymous parameter 0>");
        j.f(aVar2, "event");
        if (aVar2 == f.a.ON_START) {
            aVar.f5275f = true;
        } else if (aVar2 == f.a.ON_STOP) {
            aVar.f5275f = false;
        }
    }

    public final Bundle b(String str) {
        j.f(str, "key");
        if (!this.f5273d) {
            throw new IllegalStateException("You can consumeRestoredStateForKey only after super.onCreate of corresponding component");
        }
        Bundle bundle = this.f5272c;
        if (bundle == null) {
            return null;
        }
        Bundle bundle2 = bundle != null ? bundle.getBundle(str) : null;
        Bundle bundle3 = this.f5272c;
        if (bundle3 != null) {
            bundle3.remove(str);
        }
        Bundle bundle4 = this.f5272c;
        if (bundle4 == null || bundle4.isEmpty()) {
            this.f5272c = null;
        }
        return bundle2;
    }

    public final c c(String str) {
        j.f(str, "key");
        for (Map.Entry entry : this.f5270a) {
            j.e(entry, "components");
            String str2 = (String) entry.getKey();
            c cVar = (c) entry.getValue();
            if (j.b(str2, str)) {
                return cVar;
            }
        }
        return null;
    }

    public final void e(f fVar) {
        j.f(fVar, "lifecycle");
        if (this.f5271b) {
            throw new IllegalStateException("SavedStateRegistry was already attached.");
        }
        fVar.a(new i() { // from class: F.b
            @Override // androidx.lifecycle.i
            public final void d(k kVar, f.a aVar) {
                androidx.savedstate.a.d(this.f729a, kVar, aVar);
            }
        });
        this.f5271b = true;
    }

    public final void f(Bundle bundle) {
        if (!this.f5271b) {
            throw new IllegalStateException("You must call performAttach() before calling performRestore(Bundle).");
        }
        if (this.f5273d) {
            throw new IllegalStateException("SavedStateRegistry was already restored.");
        }
        this.f5272c = bundle != null ? bundle.getBundle("androidx.lifecycle.BundlableSavedStateRegistry.key") : null;
        this.f5273d = true;
    }

    public final void g(Bundle bundle) {
        j.f(bundle, "outBundle");
        Bundle bundle2 = new Bundle();
        Bundle bundle3 = this.f5272c;
        if (bundle3 != null) {
            bundle2.putAll(bundle3);
        }
        b.d dVarE = this.f5270a.e();
        j.e(dVarE, "this.components.iteratorWithAdditions()");
        while (dVarE.hasNext()) {
            Map.Entry entry = (Map.Entry) dVarE.next();
            bundle2.putBundle((String) entry.getKey(), ((c) entry.getValue()).a());
        }
        if (bundle2.isEmpty()) {
            return;
        }
        bundle.putBundle("androidx.lifecycle.BundlableSavedStateRegistry.key", bundle2);
    }

    public final void h(String str, c cVar) {
        j.f(str, "key");
        j.f(cVar, "provider");
        if (((c) this.f5270a.i(str, cVar)) != null) {
            throw new IllegalArgumentException("SavedStateProvider with the given key is already registered");
        }
    }

    public final void i(Class cls) {
        j.f(cls, "clazz");
        if (!this.f5275f) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
        Recreator.b bVar = this.f5274e;
        if (bVar == null) {
            bVar = new Recreator.b(this);
        }
        this.f5274e = bVar;
        try {
            cls.getDeclaredConstructor(new Class[0]);
            Recreator.b bVar2 = this.f5274e;
            if (bVar2 != null) {
                String name = cls.getName();
                j.e(name, "clazz.name");
                bVar2.b(name);
            }
        } catch (NoSuchMethodException e3) {
            throw new IllegalArgumentException("Class " + cls.getSimpleName() + " must have default constructor in order to be automatically recreated", e3);
        }
    }
}
