package i;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.ActionProvider;
import android.view.CollapsibleActionView;
import android.view.ContextMenu;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import android.widget.FrameLayout;
import androidx.core.view.AbstractC0254b;
import java.lang.reflect.Method;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: renamed from: i.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class MenuItemC0568c extends AbstractC0567b implements MenuItem {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final InterfaceMenuItemC0631b f9314d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Method f9315e;

    /* JADX INFO: renamed from: i.c$a */
    private class a extends AbstractC0254b implements ActionProvider.VisibilityListener {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private AbstractC0254b.InterfaceC0065b f9316d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final ActionProvider f9317e;

        a(Context context, ActionProvider actionProvider) {
            super(context);
            this.f9317e = actionProvider;
        }

        @Override // androidx.core.view.AbstractC0254b
        public boolean a() {
            return this.f9317e.hasSubMenu();
        }

        @Override // androidx.core.view.AbstractC0254b
        public boolean b() {
            return this.f9317e.isVisible();
        }

        @Override // androidx.core.view.AbstractC0254b
        public View c(MenuItem menuItem) {
            return this.f9317e.onCreateActionView(menuItem);
        }

        @Override // androidx.core.view.AbstractC0254b
        public boolean d() {
            return this.f9317e.onPerformDefaultAction();
        }

        @Override // androidx.core.view.AbstractC0254b
        public void e(SubMenu subMenu) {
            this.f9317e.onPrepareSubMenu(MenuItemC0568c.this.d(subMenu));
        }

        @Override // androidx.core.view.AbstractC0254b
        public boolean f() {
            return this.f9317e.overridesItemVisibility();
        }

        @Override // androidx.core.view.AbstractC0254b
        public void i(AbstractC0254b.InterfaceC0065b interfaceC0065b) {
            this.f9316d = interfaceC0065b;
            this.f9317e.setVisibilityListener(interfaceC0065b != null ? this : null);
        }

        @Override // android.view.ActionProvider.VisibilityListener
        public void onActionProviderVisibilityChanged(boolean z3) {
            AbstractC0254b.InterfaceC0065b interfaceC0065b = this.f9316d;
            if (interfaceC0065b != null) {
                interfaceC0065b.onActionProviderVisibilityChanged(z3);
            }
        }
    }

    /* JADX INFO: renamed from: i.c$b */
    static class b extends FrameLayout implements androidx.appcompat.view.c {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final CollapsibleActionView f9319b;

        /* JADX WARN: Multi-variable type inference failed */
        b(View view) {
            super(view.getContext());
            this.f9319b = (CollapsibleActionView) view;
            addView(view);
        }

        View a() {
            return (View) this.f9319b;
        }

        @Override // androidx.appcompat.view.c
        public void c() {
            this.f9319b.onActionViewExpanded();
        }

        @Override // androidx.appcompat.view.c
        public void d() {
            this.f9319b.onActionViewCollapsed();
        }
    }

    /* JADX INFO: renamed from: i.c$c, reason: collision with other inner class name */
    private class MenuItemOnActionExpandListenerC0131c implements MenuItem.OnActionExpandListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final MenuItem.OnActionExpandListener f9320a;

        MenuItemOnActionExpandListenerC0131c(MenuItem.OnActionExpandListener onActionExpandListener) {
            this.f9320a = onActionExpandListener;
        }

        @Override // android.view.MenuItem.OnActionExpandListener
        public boolean onMenuItemActionCollapse(MenuItem menuItem) {
            return this.f9320a.onMenuItemActionCollapse(MenuItemC0568c.this.c(menuItem));
        }

        @Override // android.view.MenuItem.OnActionExpandListener
        public boolean onMenuItemActionExpand(MenuItem menuItem) {
            return this.f9320a.onMenuItemActionExpand(MenuItemC0568c.this.c(menuItem));
        }
    }

    /* JADX INFO: renamed from: i.c$d */
    private class d implements MenuItem.OnMenuItemClickListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final MenuItem.OnMenuItemClickListener f9322a;

        d(MenuItem.OnMenuItemClickListener onMenuItemClickListener) {
            this.f9322a = onMenuItemClickListener;
        }

        @Override // android.view.MenuItem.OnMenuItemClickListener
        public boolean onMenuItemClick(MenuItem menuItem) {
            return this.f9322a.onMenuItemClick(MenuItemC0568c.this.c(menuItem));
        }
    }

    public MenuItemC0568c(Context context, InterfaceMenuItemC0631b interfaceMenuItemC0631b) {
        super(context);
        if (interfaceMenuItemC0631b == null) {
            throw new IllegalArgumentException("Wrapped Object can not be null.");
        }
        this.f9314d = interfaceMenuItemC0631b;
    }

    @Override // android.view.MenuItem
    public boolean collapseActionView() {
        return this.f9314d.collapseActionView();
    }

    @Override // android.view.MenuItem
    public boolean expandActionView() {
        return this.f9314d.expandActionView();
    }

    @Override // android.view.MenuItem
    public ActionProvider getActionProvider() {
        AbstractC0254b abstractC0254bB = this.f9314d.b();
        if (abstractC0254bB instanceof a) {
            return ((a) abstractC0254bB).f9317e;
        }
        return null;
    }

    @Override // android.view.MenuItem
    public View getActionView() {
        View actionView = this.f9314d.getActionView();
        return actionView instanceof b ? ((b) actionView).a() : actionView;
    }

    @Override // android.view.MenuItem
    public int getAlphabeticModifiers() {
        return this.f9314d.getAlphabeticModifiers();
    }

    @Override // android.view.MenuItem
    public char getAlphabeticShortcut() {
        return this.f9314d.getAlphabeticShortcut();
    }

    @Override // android.view.MenuItem
    public CharSequence getContentDescription() {
        return this.f9314d.getContentDescription();
    }

    @Override // android.view.MenuItem
    public int getGroupId() {
        return this.f9314d.getGroupId();
    }

    @Override // android.view.MenuItem
    public Drawable getIcon() {
        return this.f9314d.getIcon();
    }

    @Override // android.view.MenuItem
    public ColorStateList getIconTintList() {
        return this.f9314d.getIconTintList();
    }

    @Override // android.view.MenuItem
    public PorterDuff.Mode getIconTintMode() {
        return this.f9314d.getIconTintMode();
    }

    @Override // android.view.MenuItem
    public Intent getIntent() {
        return this.f9314d.getIntent();
    }

    @Override // android.view.MenuItem
    public int getItemId() {
        return this.f9314d.getItemId();
    }

    @Override // android.view.MenuItem
    public ContextMenu.ContextMenuInfo getMenuInfo() {
        return this.f9314d.getMenuInfo();
    }

    @Override // android.view.MenuItem
    public int getNumericModifiers() {
        return this.f9314d.getNumericModifiers();
    }

    @Override // android.view.MenuItem
    public char getNumericShortcut() {
        return this.f9314d.getNumericShortcut();
    }

    @Override // android.view.MenuItem
    public int getOrder() {
        return this.f9314d.getOrder();
    }

    @Override // android.view.MenuItem
    public SubMenu getSubMenu() {
        return d(this.f9314d.getSubMenu());
    }

    @Override // android.view.MenuItem
    public CharSequence getTitle() {
        return this.f9314d.getTitle();
    }

    @Override // android.view.MenuItem
    public CharSequence getTitleCondensed() {
        return this.f9314d.getTitleCondensed();
    }

    @Override // android.view.MenuItem
    public CharSequence getTooltipText() {
        return this.f9314d.getTooltipText();
    }

    public void h(boolean z3) {
        try {
            if (this.f9315e == null) {
                this.f9315e = this.f9314d.getClass().getDeclaredMethod("setExclusiveCheckable", Boolean.TYPE);
            }
            this.f9315e.invoke(this.f9314d, Boolean.valueOf(z3));
        } catch (Exception e3) {
            Log.w("MenuItemWrapper", "Error while calling setExclusiveCheckable", e3);
        }
    }

    @Override // android.view.MenuItem
    public boolean hasSubMenu() {
        return this.f9314d.hasSubMenu();
    }

    @Override // android.view.MenuItem
    public boolean isActionViewExpanded() {
        return this.f9314d.isActionViewExpanded();
    }

    @Override // android.view.MenuItem
    public boolean isCheckable() {
        return this.f9314d.isCheckable();
    }

    @Override // android.view.MenuItem
    public boolean isChecked() {
        return this.f9314d.isChecked();
    }

    @Override // android.view.MenuItem
    public boolean isEnabled() {
        return this.f9314d.isEnabled();
    }

    @Override // android.view.MenuItem
    public boolean isVisible() {
        return this.f9314d.isVisible();
    }

    @Override // android.view.MenuItem
    public MenuItem setActionProvider(ActionProvider actionProvider) {
        a aVar = new a(this.f9311a, actionProvider);
        InterfaceMenuItemC0631b interfaceMenuItemC0631b = this.f9314d;
        if (actionProvider == null) {
            aVar = null;
        }
        interfaceMenuItemC0631b.a(aVar);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setActionView(View view) {
        if (view instanceof CollapsibleActionView) {
            view = new b(view);
        }
        this.f9314d.setActionView(view);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3) {
        this.f9314d.setAlphabeticShortcut(c3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setCheckable(boolean z3) {
        this.f9314d.setCheckable(z3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setChecked(boolean z3) {
        this.f9314d.setChecked(z3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setContentDescription(CharSequence charSequence) {
        this.f9314d.setContentDescription(charSequence);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setEnabled(boolean z3) {
        this.f9314d.setEnabled(z3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(Drawable drawable) {
        this.f9314d.setIcon(drawable);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIconTintList(ColorStateList colorStateList) {
        this.f9314d.setIconTintList(colorStateList);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIconTintMode(PorterDuff.Mode mode) {
        this.f9314d.setIconTintMode(mode);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIntent(Intent intent) {
        this.f9314d.setIntent(intent);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setNumericShortcut(char c3) {
        this.f9314d.setNumericShortcut(c3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setOnActionExpandListener(MenuItem.OnActionExpandListener onActionExpandListener) {
        this.f9314d.setOnActionExpandListener(onActionExpandListener != null ? new MenuItemOnActionExpandListenerC0131c(onActionExpandListener) : null);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setOnMenuItemClickListener(MenuItem.OnMenuItemClickListener onMenuItemClickListener) {
        this.f9314d.setOnMenuItemClickListener(onMenuItemClickListener != null ? new d(onMenuItemClickListener) : null);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4) {
        this.f9314d.setShortcut(c3, c4);
        return this;
    }

    @Override // android.view.MenuItem
    public void setShowAsAction(int i3) {
        this.f9314d.setShowAsAction(i3);
    }

    @Override // android.view.MenuItem
    public MenuItem setShowAsActionFlags(int i3) {
        this.f9314d.setShowAsActionFlags(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(CharSequence charSequence) {
        this.f9314d.setTitle(charSequence);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitleCondensed(CharSequence charSequence) {
        this.f9314d.setTitleCondensed(charSequence);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTooltipText(CharSequence charSequence) {
        this.f9314d.setTooltipText(charSequence);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setVisible(boolean z3) {
        return this.f9314d.setVisible(z3);
    }

    @Override // android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3, int i3) {
        this.f9314d.setAlphabeticShortcut(c3, i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(int i3) {
        this.f9314d.setIcon(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setNumericShortcut(char c3, int i3) {
        this.f9314d.setNumericShortcut(c3, i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4, int i3, int i4) {
        this.f9314d.setShortcut(c3, c4, i3, i4);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(int i3) {
        this.f9314d.setTitle(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setActionView(int i3) {
        this.f9314d.setActionView(i3);
        View actionView = this.f9314d.getActionView();
        if (actionView instanceof CollapsibleActionView) {
            this.f9314d.setActionView(new b(actionView));
        }
        return this;
    }
}
