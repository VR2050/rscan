package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.util.SparseBooleanArray;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.view.menu.ActionMenuItemView;
import androidx.appcompat.view.menu.j;
import androidx.appcompat.view.menu.k;
import androidx.appcompat.widget.ActionMenuView;
import androidx.core.view.AbstractC0254b;
import d.AbstractC0502a;
import java.util.ArrayList;

/* JADX INFO: renamed from: androidx.appcompat.widget.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0229c extends androidx.appcompat.view.menu.a implements AbstractC0254b.a {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    a f4007A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    RunnableC0053c f4008B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private b f4009C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    final f f4010D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    int f4011E;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    d f4012l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private Drawable f4013m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f4014n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f4015o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f4016p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f4017q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f4018r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f4019s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f4020t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private boolean f4021u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f4022v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f4023w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f4024x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final SparseBooleanArray f4025y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    e f4026z;

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$a */
    private class a extends androidx.appcompat.view.menu.i {
        public a(Context context, androidx.appcompat.view.menu.m mVar, View view) {
            super(context, mVar, view, false, AbstractC0502a.f8797i);
            if (!((androidx.appcompat.view.menu.g) mVar.getItem()).l()) {
                View view2 = C0229c.this.f4012l;
                f(view2 == null ? (View) ((androidx.appcompat.view.menu.a) C0229c.this).f3433j : view2);
            }
            j(C0229c.this.f4010D);
        }

        @Override // androidx.appcompat.view.menu.i
        protected void e() {
            C0229c c0229c = C0229c.this;
            c0229c.f4007A = null;
            c0229c.f4011E = 0;
            super.e();
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$b */
    private class b extends ActionMenuItemView.b {
        b() {
        }

        @Override // androidx.appcompat.view.menu.ActionMenuItemView.b
        public i.e a() {
            a aVar = C0229c.this.f4007A;
            if (aVar != null) {
                return aVar.c();
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$c, reason: collision with other inner class name */
    private class RunnableC0053c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private e f4029b;

        public RunnableC0053c(e eVar) {
            this.f4029b = eVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (((androidx.appcompat.view.menu.a) C0229c.this).f3427d != null) {
                ((androidx.appcompat.view.menu.a) C0229c.this).f3427d.d();
            }
            View view = (View) ((androidx.appcompat.view.menu.a) C0229c.this).f3433j;
            if (view != null && view.getWindowToken() != null && this.f4029b.m()) {
                C0229c.this.f4026z = this.f4029b;
            }
            C0229c.this.f4008B = null;
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$d */
    private class d extends r implements ActionMenuView.a {

        /* JADX INFO: renamed from: androidx.appcompat.widget.c$d$a */
        class a extends S {

            /* JADX INFO: renamed from: k, reason: collision with root package name */
            final /* synthetic */ C0229c f4032k;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            a(View view, C0229c c0229c) {
                super(view);
                this.f4032k = c0229c;
            }

            @Override // androidx.appcompat.widget.S
            public i.e b() {
                e eVar = C0229c.this.f4026z;
                if (eVar == null) {
                    return null;
                }
                return eVar.c();
            }

            @Override // androidx.appcompat.widget.S
            public boolean c() {
                C0229c.this.K();
                return true;
            }

            @Override // androidx.appcompat.widget.S
            public boolean d() {
                C0229c c0229c = C0229c.this;
                if (c0229c.f4008B != null) {
                    return false;
                }
                c0229c.B();
                return true;
            }
        }

        public d(Context context) {
            super(context, null, AbstractC0502a.f8796h);
            setClickable(true);
            setFocusable(true);
            setVisibility(0);
            setEnabled(true);
            l0.a(this, getContentDescription());
            setOnTouchListener(new a(this, C0229c.this));
        }

        @Override // androidx.appcompat.widget.ActionMenuView.a
        public boolean b() {
            return false;
        }

        @Override // androidx.appcompat.widget.ActionMenuView.a
        public boolean d() {
            return false;
        }

        @Override // android.view.View
        public boolean performClick() {
            if (super.performClick()) {
                return true;
            }
            playSoundEffect(0);
            C0229c.this.K();
            return true;
        }

        @Override // android.widget.ImageView
        protected boolean setFrame(int i3, int i4, int i5, int i6) {
            boolean frame = super.setFrame(i3, i4, i5, i6);
            Drawable drawable = getDrawable();
            Drawable background = getBackground();
            if (drawable != null && background != null) {
                int width = getWidth();
                int height = getHeight();
                int iMax = Math.max(width, height) / 2;
                int paddingLeft = (width + (getPaddingLeft() - getPaddingRight())) / 2;
                int paddingTop = (height + (getPaddingTop() - getPaddingBottom())) / 2;
                androidx.core.graphics.drawable.a.d(background, paddingLeft - iMax, paddingTop - iMax, paddingLeft + iMax, paddingTop + iMax);
            }
            return frame;
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$e */
    private class e extends androidx.appcompat.view.menu.i {
        public e(Context context, androidx.appcompat.view.menu.e eVar, View view, boolean z3) {
            super(context, eVar, view, z3, AbstractC0502a.f8797i);
            h(8388613);
            j(C0229c.this.f4010D);
        }

        @Override // androidx.appcompat.view.menu.i
        protected void e() {
            if (((androidx.appcompat.view.menu.a) C0229c.this).f3427d != null) {
                ((androidx.appcompat.view.menu.a) C0229c.this).f3427d.close();
            }
            C0229c.this.f4026z = null;
            super.e();
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.widget.c$f */
    private class f implements j.a {
        f() {
        }

        @Override // androidx.appcompat.view.menu.j.a
        public void c(androidx.appcompat.view.menu.e eVar, boolean z3) {
            if (eVar instanceof androidx.appcompat.view.menu.m) {
                eVar.D().e(false);
            }
            j.a aVarM = C0229c.this.m();
            if (aVarM != null) {
                aVarM.c(eVar, z3);
            }
        }

        @Override // androidx.appcompat.view.menu.j.a
        public boolean d(androidx.appcompat.view.menu.e eVar) {
            if (eVar == ((androidx.appcompat.view.menu.a) C0229c.this).f3427d) {
                return false;
            }
            C0229c.this.f4011E = ((androidx.appcompat.view.menu.m) eVar).getItem().getItemId();
            j.a aVarM = C0229c.this.m();
            if (aVarM != null) {
                return aVarM.d(eVar);
            }
            return false;
        }
    }

    public C0229c(Context context) {
        super(context, d.g.f8912c, d.g.f8911b);
        this.f4025y = new SparseBooleanArray();
        this.f4010D = new f();
    }

    /* JADX WARN: Multi-variable type inference failed */
    private View z(MenuItem menuItem) {
        ViewGroup viewGroup = (ViewGroup) this.f3433j;
        if (viewGroup == null) {
            return null;
        }
        int childCount = viewGroup.getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = viewGroup.getChildAt(i3);
            if ((childAt instanceof k.a) && ((k.a) childAt).getItemData() == menuItem) {
                return childAt;
            }
        }
        return null;
    }

    public Drawable A() {
        d dVar = this.f4012l;
        if (dVar != null) {
            return dVar.getDrawable();
        }
        if (this.f4014n) {
            return this.f4013m;
        }
        return null;
    }

    public boolean B() {
        Object obj;
        RunnableC0053c runnableC0053c = this.f4008B;
        if (runnableC0053c != null && (obj = this.f3433j) != null) {
            ((View) obj).removeCallbacks(runnableC0053c);
            this.f4008B = null;
            return true;
        }
        e eVar = this.f4026z;
        if (eVar == null) {
            return false;
        }
        eVar.b();
        return true;
    }

    public boolean C() {
        a aVar = this.f4007A;
        if (aVar == null) {
            return false;
        }
        aVar.b();
        return true;
    }

    public boolean D() {
        return this.f4008B != null || E();
    }

    public boolean E() {
        e eVar = this.f4026z;
        return eVar != null && eVar.d();
    }

    public void F(Configuration configuration) {
        if (!this.f4020t) {
            this.f4019s = androidx.appcompat.view.a.b(this.f3426c).d();
        }
        androidx.appcompat.view.menu.e eVar = this.f3427d;
        if (eVar != null) {
            eVar.L(true);
        }
    }

    public void G(boolean z3) {
        this.f4023w = z3;
    }

    public void H(ActionMenuView actionMenuView) {
        this.f3433j = actionMenuView;
        actionMenuView.b(this.f3427d);
    }

    public void I(Drawable drawable) {
        d dVar = this.f4012l;
        if (dVar != null) {
            dVar.setImageDrawable(drawable);
        } else {
            this.f4014n = true;
            this.f4013m = drawable;
        }
    }

    public void J(boolean z3) {
        this.f4015o = z3;
        this.f4016p = true;
    }

    public boolean K() {
        androidx.appcompat.view.menu.e eVar;
        if (!this.f4015o || E() || (eVar = this.f3427d) == null || this.f3433j == null || this.f4008B != null || eVar.z().isEmpty()) {
            return false;
        }
        RunnableC0053c runnableC0053c = new RunnableC0053c(new e(this.f3426c, this.f3427d, this.f4012l, true));
        this.f4008B = runnableC0053c;
        ((View) this.f3433j).post(runnableC0053c);
        return true;
    }

    @Override // androidx.appcompat.view.menu.a
    public void b(androidx.appcompat.view.menu.g gVar, k.a aVar) {
        aVar.e(gVar, 0);
        ActionMenuItemView actionMenuItemView = (ActionMenuItemView) aVar;
        actionMenuItemView.setItemInvoker((ActionMenuView) this.f3433j);
        if (this.f4009C == null) {
            this.f4009C = new b();
        }
        actionMenuItemView.setPopupCallback(this.f4009C);
    }

    @Override // androidx.appcompat.view.menu.a, androidx.appcompat.view.menu.j
    public void c(androidx.appcompat.view.menu.e eVar, boolean z3) {
        y();
        super.c(eVar, z3);
    }

    @Override // androidx.appcompat.view.menu.a, androidx.appcompat.view.menu.j
    public void d(Context context, androidx.appcompat.view.menu.e eVar) {
        super.d(context, eVar);
        Resources resources = context.getResources();
        androidx.appcompat.view.a aVarB = androidx.appcompat.view.a.b(context);
        if (!this.f4016p) {
            this.f4015o = aVarB.f();
        }
        if (!this.f4022v) {
            this.f4017q = aVarB.c();
        }
        if (!this.f4020t) {
            this.f4019s = aVarB.d();
        }
        int measuredWidth = this.f4017q;
        if (this.f4015o) {
            if (this.f4012l == null) {
                d dVar = new d(this.f3425b);
                this.f4012l = dVar;
                if (this.f4014n) {
                    dVar.setImageDrawable(this.f4013m);
                    this.f4013m = null;
                    this.f4014n = false;
                }
                int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
                this.f4012l.measure(iMakeMeasureSpec, iMakeMeasureSpec);
            }
            measuredWidth -= this.f4012l.getMeasuredWidth();
        } else {
            this.f4012l = null;
        }
        this.f4018r = measuredWidth;
        this.f4024x = (int) (resources.getDisplayMetrics().density * 56.0f);
    }

    @Override // androidx.appcompat.view.menu.a, androidx.appcompat.view.menu.j
    public boolean e(androidx.appcompat.view.menu.m mVar) {
        boolean z3 = false;
        if (!mVar.hasVisibleItems()) {
            return false;
        }
        androidx.appcompat.view.menu.m mVar2 = mVar;
        while (mVar2.f0() != this.f3427d) {
            mVar2 = (androidx.appcompat.view.menu.m) mVar2.f0();
        }
        View viewZ = z(mVar2.getItem());
        if (viewZ == null) {
            return false;
        }
        this.f4011E = mVar.getItem().getItemId();
        int size = mVar.size();
        int i3 = 0;
        while (true) {
            if (i3 >= size) {
                break;
            }
            MenuItem item = mVar.getItem(i3);
            if (item.isVisible() && item.getIcon() != null) {
                z3 = true;
                break;
            }
            i3++;
        }
        a aVar = new a(this.f3426c, mVar, viewZ);
        this.f4007A = aVar;
        aVar.g(z3);
        this.f4007A.k();
        super.e(mVar);
        return true;
    }

    @Override // androidx.appcompat.view.menu.a, androidx.appcompat.view.menu.j
    public void f(boolean z3) {
        super.f(z3);
        ((View) this.f3433j).requestLayout();
        androidx.appcompat.view.menu.e eVar = this.f3427d;
        boolean z4 = false;
        if (eVar != null) {
            ArrayList arrayListS = eVar.s();
            int size = arrayListS.size();
            for (int i3 = 0; i3 < size; i3++) {
                AbstractC0254b abstractC0254bB = ((androidx.appcompat.view.menu.g) arrayListS.get(i3)).b();
                if (abstractC0254bB != null) {
                    abstractC0254bB.h(this);
                }
            }
        }
        androidx.appcompat.view.menu.e eVar2 = this.f3427d;
        ArrayList arrayListZ = eVar2 != null ? eVar2.z() : null;
        if (this.f4015o && arrayListZ != null) {
            int size2 = arrayListZ.size();
            if (size2 == 1) {
                z4 = !((androidx.appcompat.view.menu.g) arrayListZ.get(0)).isActionViewExpanded();
            } else if (size2 > 0) {
                z4 = true;
            }
        }
        if (z4) {
            if (this.f4012l == null) {
                this.f4012l = new d(this.f3425b);
            }
            ViewGroup viewGroup = (ViewGroup) this.f4012l.getParent();
            if (viewGroup != this.f3433j) {
                if (viewGroup != null) {
                    viewGroup.removeView(this.f4012l);
                }
                ActionMenuView actionMenuView = (ActionMenuView) this.f3433j;
                actionMenuView.addView(this.f4012l, actionMenuView.D());
            }
        } else {
            d dVar = this.f4012l;
            if (dVar != null) {
                Object parent = dVar.getParent();
                Object obj = this.f3433j;
                if (parent == obj) {
                    ((ViewGroup) obj).removeView(this.f4012l);
                }
            }
        }
        ((ActionMenuView) this.f3433j).setOverflowReserved(this.f4015o);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [androidx.appcompat.widget.c] */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v2, types: [boolean] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r0v9 */
    /* JADX WARN: Type inference failed for: r15v1, types: [androidx.appcompat.view.menu.g] */
    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1, types: [int] */
    /* JADX WARN: Type inference failed for: r3v12 */
    @Override // androidx.appcompat.view.menu.j
    public boolean h() {
        ArrayList arrayListE;
        int size;
        int i3;
        int iJ;
        ?? r02;
        int i4;
        C0229c c0229c = this;
        androidx.appcompat.view.menu.e eVar = c0229c.f3427d;
        View view = null;
        ?? r3 = 0;
        if (eVar != null) {
            arrayListE = eVar.E();
            size = arrayListE.size();
        } else {
            arrayListE = null;
            size = 0;
        }
        int i5 = c0229c.f4019s;
        int i6 = c0229c.f4018r;
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        ViewGroup viewGroup = (ViewGroup) c0229c.f3433j;
        boolean z3 = false;
        int i7 = 0;
        int i8 = 0;
        for (int i9 = 0; i9 < size; i9++) {
            androidx.appcompat.view.menu.g gVar = (androidx.appcompat.view.menu.g) arrayListE.get(i9);
            if (gVar.o()) {
                i7++;
            } else if (gVar.n()) {
                i8++;
            } else {
                z3 = true;
            }
            if (c0229c.f4023w && gVar.isActionViewExpanded()) {
                i5 = 0;
            }
        }
        if (c0229c.f4015o && (z3 || i8 + i7 > i5)) {
            i5--;
        }
        int i10 = i5 - i7;
        SparseBooleanArray sparseBooleanArray = c0229c.f4025y;
        sparseBooleanArray.clear();
        if (c0229c.f4021u) {
            int i11 = c0229c.f4024x;
            iJ = i6 / i11;
            i3 = i11 + ((i6 % i11) / iJ);
        } else {
            i3 = 0;
            iJ = 0;
        }
        int i12 = 0;
        int i13 = 0;
        ?? r03 = c0229c;
        while (i12 < size) {
            ?? r15 = (androidx.appcompat.view.menu.g) arrayListE.get(i12);
            if (r15.o()) {
                View viewN = r03.n(r15, view, viewGroup);
                if (r03.f4021u) {
                    iJ -= ActionMenuView.J(viewN, i3, iJ, iMakeMeasureSpec, r3);
                } else {
                    viewN.measure(iMakeMeasureSpec, iMakeMeasureSpec);
                }
                int measuredWidth = viewN.getMeasuredWidth();
                i6 -= measuredWidth;
                if (i13 == 0) {
                    i13 = measuredWidth;
                }
                int groupId = r15.getGroupId();
                if (groupId != 0) {
                    sparseBooleanArray.put(groupId, true);
                }
                r15.u(true);
                r02 = r3;
                i4 = size;
            } else if (r15.n()) {
                int groupId2 = r15.getGroupId();
                boolean z4 = sparseBooleanArray.get(groupId2);
                boolean z5 = (i10 > 0 || z4) && i6 > 0 && (!r03.f4021u || iJ > 0);
                boolean z6 = z5;
                i4 = size;
                if (z5) {
                    View viewN2 = r03.n(r15, null, viewGroup);
                    if (r03.f4021u) {
                        int iJ2 = ActionMenuView.J(viewN2, i3, iJ, iMakeMeasureSpec, 0);
                        iJ -= iJ2;
                        if (iJ2 == 0) {
                            z6 = false;
                        }
                    } else {
                        viewN2.measure(iMakeMeasureSpec, iMakeMeasureSpec);
                    }
                    boolean z7 = z6;
                    int measuredWidth2 = viewN2.getMeasuredWidth();
                    i6 -= measuredWidth2;
                    if (i13 == 0) {
                        i13 = measuredWidth2;
                    }
                    z5 = z7 & (!r03.f4021u ? i6 + i13 <= 0 : i6 < 0);
                }
                if (z5 && groupId2 != 0) {
                    sparseBooleanArray.put(groupId2, true);
                } else if (z4) {
                    sparseBooleanArray.put(groupId2, false);
                    for (int i14 = 0; i14 < i12; i14++) {
                        androidx.appcompat.view.menu.g gVar2 = (androidx.appcompat.view.menu.g) arrayListE.get(i14);
                        if (gVar2.getGroupId() == groupId2) {
                            if (gVar2.l()) {
                                i10++;
                            }
                            gVar2.u(false);
                        }
                    }
                }
                if (z5) {
                    i10--;
                }
                r15.u(z5);
                r02 = 0;
            } else {
                r02 = r3;
                i4 = size;
                r15.u(r02);
            }
            i12++;
            r3 = r02;
            size = i4;
            view = null;
            r03 = this;
        }
        return true;
    }

    @Override // androidx.appcompat.view.menu.a
    public boolean l(ViewGroup viewGroup, int i3) {
        if (viewGroup.getChildAt(i3) == this.f4012l) {
            return false;
        }
        return super.l(viewGroup, i3);
    }

    @Override // androidx.appcompat.view.menu.a
    public View n(androidx.appcompat.view.menu.g gVar, View view, ViewGroup viewGroup) {
        View actionView = gVar.getActionView();
        if (actionView == null || gVar.j()) {
            actionView = super.n(gVar, view, viewGroup);
        }
        actionView.setVisibility(gVar.isActionViewExpanded() ? 8 : 0);
        ActionMenuView actionMenuView = (ActionMenuView) viewGroup;
        ViewGroup.LayoutParams layoutParams = actionView.getLayoutParams();
        if (!actionMenuView.checkLayoutParams(layoutParams)) {
            actionView.setLayoutParams(actionMenuView.generateLayoutParams(layoutParams));
        }
        return actionView;
    }

    @Override // androidx.appcompat.view.menu.a
    public androidx.appcompat.view.menu.k o(ViewGroup viewGroup) {
        androidx.appcompat.view.menu.k kVar = this.f3433j;
        androidx.appcompat.view.menu.k kVarO = super.o(viewGroup);
        if (kVar != kVarO) {
            ((ActionMenuView) kVarO).setPresenter(this);
        }
        return kVarO;
    }

    @Override // androidx.appcompat.view.menu.a
    public boolean q(int i3, androidx.appcompat.view.menu.g gVar) {
        return gVar.l();
    }

    public boolean y() {
        return B() | C();
    }
}
