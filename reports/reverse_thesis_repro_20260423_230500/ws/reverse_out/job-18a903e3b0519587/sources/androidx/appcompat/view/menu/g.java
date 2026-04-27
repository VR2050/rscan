package androidx.appcompat.view.menu;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.ActionProvider;
import android.view.ContextMenu;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.appcompat.view.menu.k;
import androidx.core.view.AbstractC0254b;
import e.AbstractC0510a;
import n.InterfaceMenuItemC0631b;

/* JADX INFO: loaded from: classes.dex */
public final class g implements InterfaceMenuItemC0631b {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private View f3520A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private AbstractC0254b f3521B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private MenuItem.OnActionExpandListener f3522C;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private ContextMenu.ContextMenuInfo f3524E;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f3525a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f3526b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f3527c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f3528d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private CharSequence f3529e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private CharSequence f3530f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Intent f3531g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private char f3532h;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private char f3534j;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Drawable f3536l;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    e f3538n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private m f3539o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Runnable f3540p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private MenuItem.OnMenuItemClickListener f3541q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private CharSequence f3542r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private CharSequence f3543s;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private int f3550z;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f3533i = 4096;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f3535k = 4096;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f3537m = 0;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private ColorStateList f3544t = null;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private PorterDuff.Mode f3545u = null;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f3546v = false;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f3547w = false;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private boolean f3548x = false;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private int f3549y = 16;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private boolean f3523D = false;

    class a implements AbstractC0254b.InterfaceC0065b {
        a() {
        }

        @Override // androidx.core.view.AbstractC0254b.InterfaceC0065b
        public void onActionProviderVisibilityChanged(boolean z3) {
            g gVar = g.this;
            gVar.f3538n.K(gVar);
        }
    }

    g(e eVar, int i3, int i4, int i5, int i6, CharSequence charSequence, int i7) {
        this.f3538n = eVar;
        this.f3525a = i4;
        this.f3526b = i3;
        this.f3527c = i5;
        this.f3528d = i6;
        this.f3529e = charSequence;
        this.f3550z = i7;
    }

    private static void d(StringBuilder sb, int i3, int i4, String str) {
        if ((i3 & i4) == i4) {
            sb.append(str);
        }
    }

    private Drawable e(Drawable drawable) {
        if (drawable != null && this.f3548x && (this.f3546v || this.f3547w)) {
            drawable = androidx.core.graphics.drawable.a.j(drawable).mutate();
            if (this.f3546v) {
                androidx.core.graphics.drawable.a.g(drawable, this.f3544t);
            }
            if (this.f3547w) {
                androidx.core.graphics.drawable.a.h(drawable, this.f3545u);
            }
            this.f3548x = false;
        }
        return drawable;
    }

    boolean A() {
        return this.f3538n.I() && g() != 0;
    }

    public boolean B() {
        return (this.f3550z & 4) == 4;
    }

    @Override // n.InterfaceMenuItemC0631b
    public InterfaceMenuItemC0631b a(AbstractC0254b abstractC0254b) {
        AbstractC0254b abstractC0254b2 = this.f3521B;
        if (abstractC0254b2 != null) {
            abstractC0254b2.g();
        }
        this.f3520A = null;
        this.f3521B = abstractC0254b;
        this.f3538n.L(true);
        AbstractC0254b abstractC0254b3 = this.f3521B;
        if (abstractC0254b3 != null) {
            abstractC0254b3.i(new a());
        }
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b
    public AbstractC0254b b() {
        return this.f3521B;
    }

    public void c() {
        this.f3538n.J(this);
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean collapseActionView() {
        if ((this.f3550z & 8) == 0) {
            return false;
        }
        if (this.f3520A == null) {
            return true;
        }
        MenuItem.OnActionExpandListener onActionExpandListener = this.f3522C;
        if (onActionExpandListener == null || onActionExpandListener.onMenuItemActionCollapse(this)) {
            return this.f3538n.f(this);
        }
        return false;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean expandActionView() {
        if (!j()) {
            return false;
        }
        MenuItem.OnActionExpandListener onActionExpandListener = this.f3522C;
        if (onActionExpandListener == null || onActionExpandListener.onMenuItemActionExpand(this)) {
            return this.f3538n.k(this);
        }
        return false;
    }

    public int f() {
        return this.f3528d;
    }

    char g() {
        return this.f3538n.H() ? this.f3534j : this.f3532h;
    }

    @Override // android.view.MenuItem
    public ActionProvider getActionProvider() {
        throw new UnsupportedOperationException("This is not supported, use MenuItemCompat.getActionProvider()");
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public View getActionView() {
        View view = this.f3520A;
        if (view != null) {
            return view;
        }
        AbstractC0254b abstractC0254b = this.f3521B;
        if (abstractC0254b == null) {
            return null;
        }
        View viewC = abstractC0254b.c(this);
        this.f3520A = viewC;
        return viewC;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public int getAlphabeticModifiers() {
        return this.f3535k;
    }

    @Override // android.view.MenuItem
    public char getAlphabeticShortcut() {
        return this.f3534j;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public CharSequence getContentDescription() {
        return this.f3542r;
    }

    @Override // android.view.MenuItem
    public int getGroupId() {
        return this.f3526b;
    }

    @Override // android.view.MenuItem
    public Drawable getIcon() {
        Drawable drawable = this.f3536l;
        if (drawable != null) {
            return e(drawable);
        }
        if (this.f3537m == 0) {
            return null;
        }
        Drawable drawableB = AbstractC0510a.b(this.f3538n.u(), this.f3537m);
        this.f3537m = 0;
        this.f3536l = drawableB;
        return e(drawableB);
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public ColorStateList getIconTintList() {
        return this.f3544t;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public PorterDuff.Mode getIconTintMode() {
        return this.f3545u;
    }

    @Override // android.view.MenuItem
    public Intent getIntent() {
        return this.f3531g;
    }

    @Override // android.view.MenuItem
    public int getItemId() {
        return this.f3525a;
    }

    @Override // android.view.MenuItem
    public ContextMenu.ContextMenuInfo getMenuInfo() {
        return this.f3524E;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public int getNumericModifiers() {
        return this.f3533i;
    }

    @Override // android.view.MenuItem
    public char getNumericShortcut() {
        return this.f3532h;
    }

    @Override // android.view.MenuItem
    public int getOrder() {
        return this.f3527c;
    }

    @Override // android.view.MenuItem
    public SubMenu getSubMenu() {
        return this.f3539o;
    }

    @Override // android.view.MenuItem
    public CharSequence getTitle() {
        return this.f3529e;
    }

    @Override // android.view.MenuItem
    public CharSequence getTitleCondensed() {
        CharSequence charSequence = this.f3530f;
        return charSequence != null ? charSequence : this.f3529e;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public CharSequence getTooltipText() {
        return this.f3543s;
    }

    String h() {
        char cG = g();
        if (cG == 0) {
            return "";
        }
        Resources resources = this.f3538n.u().getResources();
        StringBuilder sb = new StringBuilder();
        if (ViewConfiguration.get(this.f3538n.u()).hasPermanentMenuKey()) {
            sb.append(resources.getString(d.h.f8940m));
        }
        int i3 = this.f3538n.H() ? this.f3535k : this.f3533i;
        d(sb, i3, 65536, resources.getString(d.h.f8936i));
        d(sb, i3, 4096, resources.getString(d.h.f8932e));
        d(sb, i3, 2, resources.getString(d.h.f8931d));
        d(sb, i3, 1, resources.getString(d.h.f8937j));
        d(sb, i3, 4, resources.getString(d.h.f8939l));
        d(sb, i3, 8, resources.getString(d.h.f8935h));
        if (cG == '\b') {
            sb.append(resources.getString(d.h.f8933f));
        } else if (cG == '\n') {
            sb.append(resources.getString(d.h.f8934g));
        } else if (cG != ' ') {
            sb.append(cG);
        } else {
            sb.append(resources.getString(d.h.f8938k));
        }
        return sb.toString();
    }

    @Override // android.view.MenuItem
    public boolean hasSubMenu() {
        return this.f3539o != null;
    }

    CharSequence i(k.a aVar) {
        return (aVar == null || !aVar.a()) ? getTitle() : getTitleCondensed();
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public boolean isActionViewExpanded() {
        return this.f3523D;
    }

    @Override // android.view.MenuItem
    public boolean isCheckable() {
        return (this.f3549y & 1) == 1;
    }

    @Override // android.view.MenuItem
    public boolean isChecked() {
        return (this.f3549y & 2) == 2;
    }

    @Override // android.view.MenuItem
    public boolean isEnabled() {
        return (this.f3549y & 16) != 0;
    }

    @Override // android.view.MenuItem
    public boolean isVisible() {
        AbstractC0254b abstractC0254b = this.f3521B;
        return (abstractC0254b == null || !abstractC0254b.f()) ? (this.f3549y & 8) == 0 : (this.f3549y & 8) == 0 && this.f3521B.b();
    }

    public boolean j() {
        AbstractC0254b abstractC0254b;
        if ((this.f3550z & 8) == 0) {
            return false;
        }
        if (this.f3520A == null && (abstractC0254b = this.f3521B) != null) {
            this.f3520A = abstractC0254b.c(this);
        }
        return this.f3520A != null;
    }

    public boolean k() {
        MenuItem.OnMenuItemClickListener onMenuItemClickListener = this.f3541q;
        if (onMenuItemClickListener != null && onMenuItemClickListener.onMenuItemClick(this)) {
            return true;
        }
        e eVar = this.f3538n;
        if (eVar.h(eVar, this)) {
            return true;
        }
        Runnable runnable = this.f3540p;
        if (runnable != null) {
            runnable.run();
            return true;
        }
        if (this.f3531g != null) {
            try {
                this.f3538n.u().startActivity(this.f3531g);
                return true;
            } catch (ActivityNotFoundException e3) {
                Log.e("MenuItemImpl", "Can't find activity to handle intent; ignoring", e3);
            }
        }
        AbstractC0254b abstractC0254b = this.f3521B;
        return abstractC0254b != null && abstractC0254b.d();
    }

    public boolean l() {
        return (this.f3549y & 32) == 32;
    }

    public boolean m() {
        return (this.f3549y & 4) != 0;
    }

    public boolean n() {
        return (this.f3550z & 1) == 1;
    }

    public boolean o() {
        return (this.f3550z & 2) == 2;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: p, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setActionView(int i3) {
        Context contextU = this.f3538n.u();
        setActionView(LayoutInflater.from(contextU).inflate(i3, (ViewGroup) new LinearLayout(contextU), false));
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setActionView(View view) {
        int i3;
        this.f3520A = view;
        this.f3521B = null;
        if (view != null && view.getId() == -1 && (i3 = this.f3525a) > 0) {
            view.setId(i3);
        }
        this.f3538n.J(this);
        return this;
    }

    public void r(boolean z3) {
        this.f3523D = z3;
        this.f3538n.L(false);
    }

    void s(boolean z3) {
        int i3 = this.f3549y;
        int i4 = (z3 ? 2 : 0) | (i3 & (-3));
        this.f3549y = i4;
        if (i3 != i4) {
            this.f3538n.L(false);
        }
    }

    @Override // android.view.MenuItem
    public MenuItem setActionProvider(ActionProvider actionProvider) {
        throw new UnsupportedOperationException("This is not supported, use MenuItemCompat.setActionProvider()");
    }

    @Override // android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3) {
        if (this.f3534j == c3) {
            return this;
        }
        this.f3534j = Character.toLowerCase(c3);
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setCheckable(boolean z3) {
        int i3 = this.f3549y;
        int i4 = (z3 ? 1 : 0) | (i3 & (-2));
        this.f3549y = i4;
        if (i3 != i4) {
            this.f3538n.L(false);
        }
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setChecked(boolean z3) {
        if ((this.f3549y & 4) != 0) {
            this.f3538n.U(this);
        } else {
            s(z3);
        }
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setEnabled(boolean z3) {
        if (z3) {
            this.f3549y |= 16;
        } else {
            this.f3549y &= -17;
        }
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(Drawable drawable) {
        this.f3537m = 0;
        this.f3536l = drawable;
        this.f3548x = true;
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setIconTintList(ColorStateList colorStateList) {
        this.f3544t = colorStateList;
        this.f3546v = true;
        this.f3548x = true;
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setIconTintMode(PorterDuff.Mode mode) {
        this.f3545u = mode;
        this.f3547w = true;
        this.f3548x = true;
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIntent(Intent intent) {
        this.f3531g = intent;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setNumericShortcut(char c3) {
        if (this.f3532h == c3) {
            return this;
        }
        this.f3532h = c3;
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setOnActionExpandListener(MenuItem.OnActionExpandListener onActionExpandListener) {
        this.f3522C = onActionExpandListener;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setOnMenuItemClickListener(MenuItem.OnMenuItemClickListener onMenuItemClickListener) {
        this.f3541q = onMenuItemClickListener;
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4) {
        this.f3532h = c3;
        this.f3534j = Character.toLowerCase(c4);
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public void setShowAsAction(int i3) {
        int i4 = i3 & 3;
        if (i4 != 0 && i4 != 1 && i4 != 2) {
            throw new IllegalArgumentException("SHOW_AS_ACTION_ALWAYS, SHOW_AS_ACTION_IF_ROOM, and SHOW_AS_ACTION_NEVER are mutually exclusive.");
        }
        this.f3550z = i3;
        this.f3538n.J(this);
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(CharSequence charSequence) {
        this.f3529e = charSequence;
        this.f3538n.L(false);
        m mVar = this.f3539o;
        if (mVar != null) {
            mVar.setHeaderTitle(charSequence);
        }
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitleCondensed(CharSequence charSequence) {
        this.f3530f = charSequence;
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setVisible(boolean z3) {
        if (y(z3)) {
            this.f3538n.K(this);
        }
        return this;
    }

    public void t(boolean z3) {
        this.f3549y = (z3 ? 4 : 0) | (this.f3549y & (-5));
    }

    public String toString() {
        CharSequence charSequence = this.f3529e;
        if (charSequence != null) {
            return charSequence.toString();
        }
        return null;
    }

    public void u(boolean z3) {
        if (z3) {
            this.f3549y |= 32;
        } else {
            this.f3549y &= -33;
        }
    }

    void v(ContextMenu.ContextMenuInfo contextMenuInfo) {
        this.f3524E = contextMenuInfo;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    /* JADX INFO: renamed from: w, reason: merged with bridge method [inline-methods] */
    public InterfaceMenuItemC0631b setShowAsActionFlags(int i3) {
        setShowAsAction(i3);
        return this;
    }

    public void x(m mVar) {
        this.f3539o = mVar;
        mVar.setHeaderTitle(getTitle());
    }

    boolean y(boolean z3) {
        int i3 = this.f3549y;
        int i4 = (z3 ? 0 : 8) | (i3 & (-9));
        this.f3549y = i4;
        return i3 != i4;
    }

    public boolean z() {
        return this.f3538n.A();
    }

    @Override // android.view.MenuItem
    public InterfaceMenuItemC0631b setContentDescription(CharSequence charSequence) {
        this.f3542r = charSequence;
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public InterfaceMenuItemC0631b setTooltipText(CharSequence charSequence) {
        this.f3543s = charSequence;
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setAlphabeticShortcut(char c3, int i3) {
        if (this.f3534j == c3 && this.f3535k == i3) {
            return this;
        }
        this.f3534j = Character.toLowerCase(c3);
        this.f3535k = KeyEvent.normalizeMetaState(i3);
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setNumericShortcut(char c3, int i3) {
        if (this.f3532h == c3 && this.f3533i == i3) {
            return this;
        }
        this.f3532h = c3;
        this.f3533i = KeyEvent.normalizeMetaState(i3);
        this.f3538n.L(false);
        return this;
    }

    @Override // n.InterfaceMenuItemC0631b, android.view.MenuItem
    public MenuItem setShortcut(char c3, char c4, int i3, int i4) {
        this.f3532h = c3;
        this.f3533i = KeyEvent.normalizeMetaState(i3);
        this.f3534j = Character.toLowerCase(c4);
        this.f3535k = KeyEvent.normalizeMetaState(i4);
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setIcon(int i3) {
        this.f3536l = null;
        this.f3537m = i3;
        this.f3548x = true;
        this.f3538n.L(false);
        return this;
    }

    @Override // android.view.MenuItem
    public MenuItem setTitle(int i3) {
        return setTitle(this.f3538n.u().getString(i3));
    }
}
