package androidx.appcompat.view;

import android.content.Context;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.view.b;
import i.MenuItemC0568c;
import java.util.ArrayList;
import l.C0612g;
import n.InterfaceMenuC0630a;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: loaded from: classes.dex */
public class f extends ActionMode {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Context f3336a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final b f3337b;

    public static class a implements b.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final ActionMode.Callback f3338a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final Context f3339b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final ArrayList f3340c = new ArrayList();

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final C0612g f3341d = new C0612g();

        public a(Context context, ActionMode.Callback callback) {
            this.f3339b = context;
            this.f3338a = callback;
        }

        private Menu f(Menu menu) {
            Menu menu2 = (Menu) this.f3341d.get(menu);
            if (menu2 != null) {
                return menu2;
            }
            i.d dVar = new i.d(this.f3339b, (InterfaceMenuC0630a) menu);
            this.f3341d.put(menu, dVar);
            return dVar;
        }

        @Override // androidx.appcompat.view.b.a
        public boolean a(b bVar, Menu menu) {
            return this.f3338a.onPrepareActionMode(e(bVar), f(menu));
        }

        @Override // androidx.appcompat.view.b.a
        public void b(b bVar) {
            this.f3338a.onDestroyActionMode(e(bVar));
        }

        @Override // androidx.appcompat.view.b.a
        public boolean c(b bVar, MenuItem menuItem) {
            return this.f3338a.onActionItemClicked(e(bVar), new MenuItemC0568c(this.f3339b, (InterfaceMenuItemC0631b) menuItem));
        }

        @Override // androidx.appcompat.view.b.a
        public boolean d(b bVar, Menu menu) {
            return this.f3338a.onCreateActionMode(e(bVar), f(menu));
        }

        public ActionMode e(b bVar) {
            int size = this.f3340c.size();
            for (int i3 = 0; i3 < size; i3++) {
                f fVar = (f) this.f3340c.get(i3);
                if (fVar != null && fVar.f3337b == bVar) {
                    return fVar;
                }
            }
            f fVar2 = new f(this.f3339b, bVar);
            this.f3340c.add(fVar2);
            return fVar2;
        }
    }

    public f(Context context, b bVar) {
        this.f3336a = context;
        this.f3337b = bVar;
    }

    @Override // android.view.ActionMode
    public void finish() {
        this.f3337b.c();
    }

    @Override // android.view.ActionMode
    public View getCustomView() {
        return this.f3337b.d();
    }

    @Override // android.view.ActionMode
    public Menu getMenu() {
        return new i.d(this.f3336a, (InterfaceMenuC0630a) this.f3337b.e());
    }

    @Override // android.view.ActionMode
    public MenuInflater getMenuInflater() {
        return this.f3337b.f();
    }

    @Override // android.view.ActionMode
    public CharSequence getSubtitle() {
        return this.f3337b.g();
    }

    @Override // android.view.ActionMode
    public Object getTag() {
        return this.f3337b.h();
    }

    @Override // android.view.ActionMode
    public CharSequence getTitle() {
        return this.f3337b.i();
    }

    @Override // android.view.ActionMode
    public boolean getTitleOptionalHint() {
        return this.f3337b.j();
    }

    @Override // android.view.ActionMode
    public void invalidate() {
        this.f3337b.k();
    }

    @Override // android.view.ActionMode
    public boolean isTitleOptional() {
        return this.f3337b.l();
    }

    @Override // android.view.ActionMode
    public void setCustomView(View view) {
        this.f3337b.m(view);
    }

    @Override // android.view.ActionMode
    public void setSubtitle(CharSequence charSequence) {
        this.f3337b.o(charSequence);
    }

    @Override // android.view.ActionMode
    public void setTag(Object obj) {
        this.f3337b.p(obj);
    }

    @Override // android.view.ActionMode
    public void setTitle(CharSequence charSequence) {
        this.f3337b.r(charSequence);
    }

    @Override // android.view.ActionMode
    public void setTitleOptionalHint(boolean z3) {
        this.f3337b.s(z3);
    }

    @Override // android.view.ActionMode
    public void setSubtitle(int i3) {
        this.f3337b.n(i3);
    }

    @Override // android.view.ActionMode
    public void setTitle(int i3) {
        this.f3337b.q(i3);
    }
}
