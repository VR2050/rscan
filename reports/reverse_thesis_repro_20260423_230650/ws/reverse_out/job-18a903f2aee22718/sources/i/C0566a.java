package i;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.view.ActionProvider;
import android.view.ContextMenu;
import android.view.KeyEvent;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import androidx.core.view.AbstractC0254b;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: renamed from: i.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0566a implements InterfaceMenuItemC0631b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f9291a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f9292b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f9293c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private CharSequence f9294d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private CharSequence f9295e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Intent f9296f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private char f9297g;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private char f9299i;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Drawable f9301k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Context f9302l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private MenuItem.OnMenuItemClickListener f9303m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private CharSequence f9304n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private CharSequence f9305o;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f9298h = 4096;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f9300j = 4096;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private ColorStateList f9306p = null;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private PorterDuff.Mode f9307q = null;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f9308r = false;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f9309s = false;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private int f9310t = 16;

    public C0566a(Context context, int i3, int i4, int i5, int i6, CharSequence charSequence) {
        this.f9302l = context;
        this.f9291a = i4;
        this.f9292b = i3;
        this.f9293c = i6;
        this.f9294d = charSequence;
    }

    private void c() {
        Drawable drawable = this.f9301k;
        if (drawable != null) {
            if (this.f9308r || this.f9309s) {
                Drawable drawableJ = androidx.core.graphics.drawable.a.j(drawable);
                this.f9301k = drawableJ;
                Drawable drawableMutate = drawableJ.mutate();
                this.f9301k = drawableMutate;
                if (this.f9308r) {
                    androidx.core.graphics.drawable.a.g(drawableMutate, this.f9306p);
                }
                if (this.f9309s) {
                    androidx.core.graphics.drawable.a.h(this.f9301k, this.f9307q);
                }
            }
        }
    }

    @Override // n.InterfaceMenuItemC0631b
    public InterfaceMenuItemC0631b a(AbstractC0254b abstractC0254b) {
        throw new UnsupportedOperationException();
    }

    @Override // n.InterfaceMenuItemC0631b
    public AbstractC0254b b() {
        return null;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean collapseActionView() {
        return false;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setActionView(int i3) {
        throw new UnsupportedOperationException();
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setActionView(View view) {
        throw new UnsupportedOperationException();
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean expandActionView() {
        return false;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setShowAsActionFlags(int i3) {
        setShowAsAction(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public ActionProvider getActionProvider() {
        throw new UnsupportedOperationException();
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public View getActionView() {
        return null;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public int getAlphabeticModifiers() {
        return this.f9300j;
    }

    @Override // android.view.MenuItem
    public char getAlphabeticShortcut() {
        return this.f9299i;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public CharSequence getContentDescription() {
        return this.f9304n;
    }

    @Override // android.view.MenuItem
    public int getGroupId() {
        return this.f9292b;
    }

    @Override // android.view.MenuItem
    public Drawable getIcon() {
        return this.f9301k;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public ColorStateList getIconTintList() {
        return this.f9306p;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public PorterDuff.Mode getIconTintMode() {
        return this.f9307q;
    }

    @Override // android.view.MenuItem
    public Intent getIntent() {
        return this.f9296f;
    }

    @Override // android.view.MenuItem
    public int getItemId() {
        return this.f9291a;
    }

    @Override // android.view.MenuItem
    public ContextMenu.ContextMenuInfo getMenuInfo() {
        return null;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public int getNumericModifiers() {
        return this.f9298h;
    }

    @Override // android.view.MenuItem
    public char getNumericShortcut() {
        return this.f9297g;
    }

    @Override // android.view.MenuItem
    public int getOrder() {
        return this.f9293c;
    }

    @Override // android.view.MenuItem
    public SubMenu getSubMenu() {
        return null;
    }

    @Override // android.view.MenuItem
    public CharSequence getTitle() {
        return this.f9294d;
    }

    @Override // android.view.MenuItem
    public CharSequence getTitleCondensed() {
        CharSequence charSequence = this.f9295e;
        return charSequence != null ? charSequence : this.f9294d;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public CharSequence getTooltipText() {
        return this.f9305o;
    }

    @Override // android.view.MenuItem
    public boolean hasSubMenu() {
        return false;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean isActionViewExpanded() {
        return false;
    }

    @Override // android.view.MenuItem
    public boolean isCheckable() {
        return (this.f9310t & 1) != 0;
    }

    @Override // android.view.MenuItem
    public boolean isChecked() {
        return (this.f9310t & 2) != 0;
    }

    @Override // android.view.MenuItem
    public boolean isEnabled() {
        return (this.f9310t & 16) != 0;
    }

    @Override // android.view.MenuItem
    public boolean isVisible() {
        return (this.f9310t & 8) == 0;
    }

    @Override // android.view.MenuItem
    public MenuItem setActionProvider(ActionProvider actionProvider) {
        throw new UnsupportedOperationException();
    }

    @Override // android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3) {
        this.f9299i = Character.toLowerCase(c3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setCheckable(boolean z3) {
        this.f9310t = (z3 ? 1 : 0) | (this.f9310t & (-2));
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setChecked(boolean z3) {
        this.f9310t = (z3 ? 2 : 0) | (this.f9310t & (-3));
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setEnabled(boolean z3) {
        this.f9310t = (z3 ? 16 : 0) | (this.f9310t & (-17));
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(Drawable drawable) {
        this.f9301k = drawable;
        c();
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setIconTintList(ColorStateList colorStateList) {
        this.f9306p = colorStateList;
        this.f9308r = true;
        c();
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setIconTintMode(PorterDuff.Mode mode) {
        this.f9307q = mode;
        this.f9309s = true;
        c();
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIntent(Intent intent) {
        this.f9296f = intent;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setNumericShortcut(char c3) {
        this.f9297g = c3;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setOnActionExpandListener(MenuItem.OnActionExpandListener onActionExpandListener) {
        throw new UnsupportedOperationException();
    }

    @Override // android.view.MenuItem
    public MenuItem setOnMenuItemClickListener(MenuItem.OnMenuItemClickListener onMenuItemClickListener) {
        this.f9303m = onMenuItemClickListener;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4) {
        this.f9297g = c3;
        this.f9299i = Character.toLowerCase(c4);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(CharSequence charSequence) {
        this.f9294d = charSequence;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitleCondensed(CharSequence charSequence) {
        this.f9295e = charSequence;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setVisible(boolean z3) {
        this.f9310t = (this.f9310t & 8) | (z3 ? 0 : 8);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3, int i3) {
        this.f9299i = Character.toLowerCase(c3);
        this.f9300j = KeyEvent.normalizeMetaState(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public InterfaceMenuItemC0631b setContentDescription(CharSequence charSequence) {
        this.f9304n = charSequence;
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setNumericShortcut(char c3, int i3) {
        this.f9297g = c3;
        this.f9298h = KeyEvent.normalizeMetaState(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(int i3) {
        this.f9294d = this.f9302l.getResources().getString(i3);
        return this;
    }

    @Override // android.view.MenuItem
    public InterfaceMenuItemC0631b setTooltipText(CharSequence charSequence) {
        this.f9305o = charSequence;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(int i3) {
        this.f9301k = androidx.core.content.a.d(this.f9302l, i3);
        c();
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4, int i3, int i4) {
        this.f9297g = c3;
        this.f9298h = KeyEvent.normalizeMetaState(i3);
        this.f9299i = Character.toLowerCase(c4);
        this.f9300j = KeyEvent.normalizeMetaState(i4);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public void setShowAsAction(int i3) {
    }
}
