package a;

import android.content.Context;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import t2.j;

/* JADX INFO: renamed from: a.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0213a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Set f2911a = new CopyOnWriteArraySet();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private volatile Context f2912b;

    public final void a(InterfaceC0214b interfaceC0214b) {
        j.f(interfaceC0214b, "listener");
        Context context = this.f2912b;
        if (context != null) {
            interfaceC0214b.a(context);
        }
        this.f2911a.add(interfaceC0214b);
    }

    public final void b() {
        this.f2912b = null;
    }

    public final void c(Context context) {
        j.f(context, "context");
        this.f2912b = context;
        Iterator it = this.f2911a.iterator();
        while (it.hasNext()) {
            ((InterfaceC0214b) it.next()).a(context);
        }
    }
}
