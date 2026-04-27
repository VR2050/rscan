package androidx.appcompat.app;

import a.InterfaceC0214b;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import androidx.appcompat.view.b;
import androidx.appcompat.widget.q0;
import androidx.core.app.n;
import androidx.fragment.app.AbstractActivityC0298j;
import androidx.lifecycle.D;
import androidx.lifecycle.E;
import androidx.savedstate.a;

/* JADX INFO: loaded from: classes.dex */
public abstract class c extends AbstractActivityC0298j implements d, n.a {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private f f3128A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private Resources f3129B;

    class a implements a.c {
        a() {
        }

        @Override // androidx.savedstate.a.c
        public Bundle a() {
            Bundle bundle = new Bundle();
            c.this.c0().D(bundle);
            return bundle;
        }
    }

    class b implements InterfaceC0214b {
        b() {
        }

        @Override // a.InterfaceC0214b
        public void a(Context context) {
            f fVarC0 = c.this.c0();
            fVarC0.u();
            fVarC0.z(c.this.b().b("androidx:appcompat"));
        }
    }

    public c() {
        e0();
    }

    private void H() {
        D.a(getWindow().getDecorView(), this);
        E.a(getWindow().getDecorView(), this);
        F.e.a(getWindow().getDecorView(), this);
        androidx.activity.r.a(getWindow().getDecorView(), this);
    }

    private void e0() {
        b().h("androidx:appcompat", new a());
        D(new b());
    }

    private boolean l0(KeyEvent keyEvent) {
        Window window;
        return (Build.VERSION.SDK_INT >= 26 || keyEvent.isCtrlPressed() || KeyEvent.metaStateHasNoModifiers(keyEvent.getMetaState()) || keyEvent.getRepeatCount() != 0 || KeyEvent.isModifierKey(keyEvent.getKeyCode()) || (window = getWindow()) == null || window.getDecorView() == null || !window.getDecorView().dispatchKeyShortcutEvent(keyEvent)) ? false : true;
    }

    @Override // android.app.Activity
    public void addContentView(View view, ViewGroup.LayoutParams layoutParams) {
        H();
        c0().e(view, layoutParams);
    }

    @Override // android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    protected void attachBaseContext(Context context) {
        super.attachBaseContext(c0().i(context));
    }

    public f c0() {
        if (this.f3128A == null) {
            this.f3128A = f.j(this, this);
        }
        return this.f3128A;
    }

    @Override // android.app.Activity
    public void closeOptionsMenu() {
        androidx.appcompat.app.a aVarD0 = d0();
        if (getWindow().hasFeature(0)) {
            if (aVarD0 == null || !aVarD0.g()) {
                super.closeOptionsMenu();
            }
        }
    }

    public androidx.appcompat.app.a d0() {
        return c0().t();
    }

    @Override // androidx.core.app.f, android.app.Activity, android.view.Window.Callback
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        androidx.appcompat.app.a aVarD0 = d0();
        if (keyCode == 82 && aVarD0 != null && aVarD0.p(keyEvent)) {
            return true;
        }
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // androidx.appcompat.app.d
    public void f(androidx.appcompat.view.b bVar) {
    }

    public void f0(androidx.core.app.n nVar) {
        nVar.b(this);
    }

    @Override // android.app.Activity
    public View findViewById(int i3) {
        return c0().l(i3);
    }

    protected void g0(androidx.core.os.c cVar) {
    }

    @Override // android.app.Activity
    public MenuInflater getMenuInflater() {
        return c0().r();
    }

    @Override // android.view.ContextThemeWrapper, android.content.ContextWrapper, android.content.Context
    public Resources getResources() {
        if (this.f3129B == null && q0.c()) {
            this.f3129B = new q0(this, super.getResources());
        }
        Resources resources = this.f3129B;
        return resources == null ? super.getResources() : resources;
    }

    @Override // androidx.appcompat.app.d
    public void h(androidx.appcompat.view.b bVar) {
    }

    protected void h0(int i3) {
    }

    public void i0(androidx.core.app.n nVar) {
    }

    @Override // android.app.Activity
    public void invalidateOptionsMenu() {
        c0().v();
    }

    public void j0() {
    }

    public boolean k0() {
        Intent intentO = o();
        if (intentO == null) {
            return false;
        }
        if (!n0(intentO)) {
            m0(intentO);
            return true;
        }
        androidx.core.app.n nVarE = androidx.core.app.n.e(this);
        f0(nVarE);
        i0(nVarE);
        nVarE.f();
        try {
            androidx.core.app.b.i(this);
            return true;
        } catch (IllegalStateException unused) {
            finish();
            return true;
        }
    }

    public void m0(Intent intent) {
        androidx.core.app.h.e(this, intent);
    }

    public boolean n0(Intent intent) {
        return androidx.core.app.h.f(this, intent);
    }

    @Override // androidx.core.app.n.a
    public Intent o() {
        return androidx.core.app.h.a(this);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        c0().y(configuration);
        if (this.f3129B != null) {
            this.f3129B.updateConfiguration(super.getResources().getConfiguration(), super.getResources().getDisplayMetrics());
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onContentChanged() {
        j0();
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        c0().A();
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyDown(int i3, KeyEvent keyEvent) {
        if (l0(keyEvent)) {
            return true;
        }
        return super.onKeyDown(i3, keyEvent);
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, androidx.activity.ComponentActivity, android.app.Activity, android.view.Window.Callback
    public final boolean onMenuItemSelected(int i3, MenuItem menuItem) {
        if (super.onMenuItemSelected(i3, menuItem)) {
            return true;
        }
        androidx.appcompat.app.a aVarD0 = d0();
        if (menuItem.getItemId() != 16908332 || aVarD0 == null || (aVarD0.j() & 4) == 0) {
            return false;
        }
        return k0();
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onMenuOpened(int i3, Menu menu) {
        return super.onMenuOpened(i3, menu);
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity, android.view.Window.Callback
    public void onPanelClosed(int i3, Menu menu) {
        super.onPanelClosed(i3, menu);
    }

    @Override // android.app.Activity
    protected void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        c0().B(bundle);
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onPostResume() {
        super.onPostResume();
        c0().C();
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onStart() {
        super.onStart();
        c0().E();
    }

    @Override // androidx.fragment.app.AbstractActivityC0298j, android.app.Activity
    protected void onStop() {
        super.onStop();
        c0().F();
    }

    @Override // android.app.Activity
    protected void onTitleChanged(CharSequence charSequence, int i3) {
        super.onTitleChanged(charSequence, i3);
        c0().P(charSequence);
    }

    @Override // android.app.Activity
    public void openOptionsMenu() {
        androidx.appcompat.app.a aVarD0 = d0();
        if (getWindow().hasFeature(0)) {
            if (aVarD0 == null || !aVarD0.q()) {
                super.openOptionsMenu();
            }
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void setContentView(int i3) {
        H();
        c0().J(i3);
    }

    @Override // android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper, android.content.Context
    public void setTheme(int i3) {
        super.setTheme(i3);
        c0().O(i3);
    }

    @Override // androidx.appcompat.app.d
    public androidx.appcompat.view.b v(b.a aVar) {
        return null;
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void setContentView(View view) {
        H();
        c0().K(view);
    }

    @Override // android.app.Activity
    public void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        H();
        c0().L(view, layoutParams);
    }
}
