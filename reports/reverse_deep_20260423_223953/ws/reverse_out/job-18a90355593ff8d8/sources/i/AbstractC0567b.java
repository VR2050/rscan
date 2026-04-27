package i;

import android.content.Context;
import android.view.MenuItem;
import android.view.SubMenu;
import l.C0612g;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: renamed from: i.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
abstract class AbstractC0567b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Context f9311a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private C0612g f9312b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private C0612g f9313c;

    AbstractC0567b(Context context) {
        this.f9311a = context;
    }

    final MenuItem c(MenuItem menuItem) {
        if (!(menuItem instanceof InterfaceMenuItemC0631b)) {
            return menuItem;
        }
        InterfaceMenuItemC0631b interfaceMenuItemC0631b = (InterfaceMenuItemC0631b) menuItem;
        if (this.f9312b == null) {
            this.f9312b = new C0612g();
        }
        MenuItem menuItem2 = (MenuItem) this.f9312b.get(interfaceMenuItemC0631b);
        if (menuItem2 != null) {
            return menuItem2;
        }
        MenuItemC0568c menuItemC0568c = new MenuItemC0568c(this.f9311a, interfaceMenuItemC0631b);
        this.f9312b.put(interfaceMenuItemC0631b, menuItemC0568c);
        return menuItemC0568c;
    }

    final void e() {
        C0612g c0612g = this.f9312b;
        if (c0612g != null) {
            c0612g.clear();
        }
        C0612g c0612g2 = this.f9313c;
        if (c0612g2 != null) {
            c0612g2.clear();
        }
    }

    final void f(int i3) {
        if (this.f9312b == null) {
            return;
        }
        int i4 = 0;
        while (i4 < this.f9312b.size()) {
            if (((InterfaceMenuItemC0631b) this.f9312b.i(i4)).getGroupId() == i3) {
                this.f9312b.j(i4);
                i4--;
            }
            i4++;
        }
    }

    final void g(int i3) {
        if (this.f9312b == null) {
            return;
        }
        for (int i4 = 0; i4 < this.f9312b.size(); i4++) {
            if (((InterfaceMenuItemC0631b) this.f9312b.i(i4)).getItemId() == i3) {
                this.f9312b.j(i4);
                return;
            }
        }
    }

    final SubMenu d(SubMenu subMenu) {
        return subMenu;
    }
}
