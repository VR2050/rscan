package androidx.lifecycle;

import android.content.Context;
import androidx.lifecycle.s;
import i2.AbstractC0586n;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class ProcessLifecycleInitializer implements G.a {
    @Override // G.a
    public List a() {
        return AbstractC0586n.g();
    }

    @Override // G.a
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public k b(Context context) {
        t2.j.f(context, "context");
        androidx.startup.a aVarE = androidx.startup.a.e(context);
        t2.j.e(aVarE, "getInstance(context)");
        if (!aVarE.g(ProcessLifecycleInitializer.class)) {
            throw new IllegalStateException("ProcessLifecycleInitializer cannot be initialized lazily.\n               Please ensure that you have:\n               <meta-data\n                   android:name='androidx.lifecycle.ProcessLifecycleInitializer'\n                   android:value='androidx.startup' />\n               under InitializationProvider in your AndroidManifest.xml");
        }
        h.a(context);
        s.b bVar = s.f5159j;
        bVar.b(context);
        return bVar.a();
    }
}
