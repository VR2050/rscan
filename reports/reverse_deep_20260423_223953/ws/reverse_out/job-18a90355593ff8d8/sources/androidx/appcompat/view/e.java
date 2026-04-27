package androidx.appcompat.view;

import android.content.Context;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.view.b;
import androidx.appcompat.view.menu.e;
import androidx.appcompat.widget.ActionBarContextView;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
public class e extends b implements e.a {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Context f3329d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private ActionBarContextView f3330e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private b.a f3331f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private WeakReference f3332g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3333h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f3334i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private androidx.appcompat.view.menu.e f3335j;

    public e(Context context, ActionBarContextView actionBarContextView, b.a aVar, boolean z3) {
        this.f3329d = context;
        this.f3330e = actionBarContextView;
        this.f3331f = aVar;
        androidx.appcompat.view.menu.e eVarT = new androidx.appcompat.view.menu.e(actionBarContextView.getContext()).T(1);
        this.f3335j = eVarT;
        eVarT.S(this);
        this.f3334i = z3;
    }

    @Override // androidx.appcompat.view.menu.e.a
    public boolean a(androidx.appcompat.view.menu.e eVar, MenuItem menuItem) {
        return this.f3331f.c(this, menuItem);
    }

    @Override // androidx.appcompat.view.menu.e.a
    public void b(androidx.appcompat.view.menu.e eVar) {
        k();
        this.f3330e.l();
    }

    @Override // androidx.appcompat.view.b
    public void c() {
        if (this.f3333h) {
            return;
        }
        this.f3333h = true;
        this.f3331f.b(this);
    }

    @Override // androidx.appcompat.view.b
    public View d() {
        WeakReference weakReference = this.f3332g;
        if (weakReference != null) {
            return (View) weakReference.get();
        }
        return null;
    }

    @Override // androidx.appcompat.view.b
    public Menu e() {
        return this.f3335j;
    }

    @Override // androidx.appcompat.view.b
    public MenuInflater f() {
        return new g(this.f3330e.getContext());
    }

    @Override // androidx.appcompat.view.b
    public CharSequence g() {
        return this.f3330e.getSubtitle();
    }

    @Override // androidx.appcompat.view.b
    public CharSequence i() {
        return this.f3330e.getTitle();
    }

    @Override // androidx.appcompat.view.b
    public void k() {
        this.f3331f.a(this, this.f3335j);
    }

    @Override // androidx.appcompat.view.b
    public boolean l() {
        return this.f3330e.j();
    }

    @Override // androidx.appcompat.view.b
    public void m(View view) {
        this.f3330e.setCustomView(view);
        this.f3332g = view != null ? new WeakReference(view) : null;
    }

    @Override // androidx.appcompat.view.b
    public void n(int i3) {
        o(this.f3329d.getString(i3));
    }

    @Override // androidx.appcompat.view.b
    public void o(CharSequence charSequence) {
        this.f3330e.setSubtitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public void q(int i3) {
        r(this.f3329d.getString(i3));
    }

    @Override // androidx.appcompat.view.b
    public void r(CharSequence charSequence) {
        this.f3330e.setTitle(charSequence);
    }

    @Override // androidx.appcompat.view.b
    public void s(boolean z3) {
        super.s(z3);
        this.f3330e.setTitleOptional(z3);
    }
}
