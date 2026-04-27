package androidx.lifecycle;

import android.os.Bundle;
import androidx.savedstate.a;
import h2.AbstractC0558d;
import java.util.Iterator;
import java.util.Map;
import kotlin.Lazy;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class w implements a.c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final androidx.savedstate.a f5177a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f5178b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Bundle f5179c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Lazy f5180d;

    static final class a extends t2.k implements InterfaceC0688a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ C f5181c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(C c3) {
            super(0);
            this.f5181c = c3;
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final x a() {
            return v.b(this.f5181c);
        }
    }

    public w(androidx.savedstate.a aVar, C c3) {
        t2.j.f(aVar, "savedStateRegistry");
        t2.j.f(c3, "viewModelStoreOwner");
        this.f5177a = aVar;
        this.f5180d = AbstractC0558d.b(new a(c3));
    }

    private final x b() {
        return (x) this.f5180d.getValue();
    }

    @Override // androidx.savedstate.a.c
    public Bundle a() {
        Bundle bundle = new Bundle();
        Bundle bundle2 = this.f5179c;
        if (bundle2 != null) {
            bundle.putAll(bundle2);
        }
        Iterator it = b().e().entrySet().iterator();
        if (!it.hasNext()) {
            this.f5178b = false;
            return bundle;
        }
        Map.Entry entry = (Map.Entry) it.next();
        androidx.activity.result.d.a(entry.getValue());
        throw null;
    }

    public final void c() {
        if (this.f5178b) {
            return;
        }
        Bundle bundleB = this.f5177a.b("androidx.lifecycle.internal.SavedStateHandlesProvider");
        Bundle bundle = new Bundle();
        Bundle bundle2 = this.f5179c;
        if (bundle2 != null) {
            bundle.putAll(bundle2);
        }
        if (bundleB != null) {
            bundle.putAll(bundleB);
        }
        this.f5179c = bundle;
        this.f5178b = true;
        b();
    }
}
