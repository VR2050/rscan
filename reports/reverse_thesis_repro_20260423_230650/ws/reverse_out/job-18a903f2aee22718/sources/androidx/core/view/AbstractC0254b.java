package androidx.core.view;

import android.content.Context;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;

/* JADX INFO: renamed from: androidx.core.view.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0254b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f4444a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private a f4445b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private InterfaceC0065b f4446c;

    /* JADX INFO: renamed from: androidx.core.view.b$a */
    public interface a {
    }

    /* JADX INFO: renamed from: androidx.core.view.b$b, reason: collision with other inner class name */
    public interface InterfaceC0065b {
        void onActionProviderVisibilityChanged(boolean z3);
    }

    public AbstractC0254b(Context context) {
        this.f4444a = context;
    }

    public abstract boolean a();

    public abstract boolean b();

    public abstract View c(MenuItem menuItem);

    public abstract boolean d();

    public abstract void e(SubMenu subMenu);

    public abstract boolean f();

    public void g() {
        this.f4446c = null;
        this.f4445b = null;
    }

    public void h(a aVar) {
        this.f4445b = aVar;
    }

    public abstract void i(InterfaceC0065b interfaceC0065b);
}
