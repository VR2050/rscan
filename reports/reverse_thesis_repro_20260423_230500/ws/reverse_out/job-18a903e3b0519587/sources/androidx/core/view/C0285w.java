package androidx.core.view;

import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/* JADX INFO: renamed from: androidx.core.view.w, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0285w {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Runnable f4518a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final CopyOnWriteArrayList f4519b = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Map f4520c = new HashMap();

    public C0285w(Runnable runnable) {
        this.f4518a = runnable;
    }

    public void a(InterfaceC0287y interfaceC0287y) {
        this.f4519b.add(interfaceC0287y);
        this.f4518a.run();
    }

    public void b(Menu menu, MenuInflater menuInflater) {
        Iterator it = this.f4519b.iterator();
        while (it.hasNext()) {
            ((InterfaceC0287y) it.next()).c(menu, menuInflater);
        }
    }

    public void c(Menu menu) {
        Iterator it = this.f4519b.iterator();
        while (it.hasNext()) {
            ((InterfaceC0287y) it.next()).b(menu);
        }
    }

    public boolean d(MenuItem menuItem) {
        Iterator it = this.f4519b.iterator();
        while (it.hasNext()) {
            if (((InterfaceC0287y) it.next()).a(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void e(Menu menu) {
        Iterator it = this.f4519b.iterator();
        while (it.hasNext()) {
            ((InterfaceC0287y) it.next()).d(menu);
        }
    }

    public void f(InterfaceC0287y interfaceC0287y) {
        this.f4519b.remove(interfaceC0287y);
        androidx.activity.result.d.a(this.f4520c.remove(interfaceC0287y));
        this.f4518a.run();
    }
}
