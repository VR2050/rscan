package androidx.appcompat.widget;

import android.content.Context;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.view.C0261e0;
import d.AbstractC0502a;

/* JADX INFO: loaded from: classes.dex */
public class ActionBarContextView extends AbstractC0227a {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private CharSequence f3630j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private CharSequence f3631k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private View f3632l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private View f3633m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private View f3634n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private LinearLayout f3635o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private TextView f3636p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private TextView f3637q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f3638r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f3639s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f3640t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private int f3641u;

    class a implements View.OnClickListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ androidx.appcompat.view.b f3642b;

        a(androidx.appcompat.view.b bVar) {
            this.f3642b = bVar;
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            this.f3642b.c();
        }
    }

    public ActionBarContextView(Context context) {
        this(context, null);
    }

    private void i() {
        if (this.f3635o == null) {
            LayoutInflater.from(getContext()).inflate(d.g.f8910a, this);
            LinearLayout linearLayout = (LinearLayout) getChildAt(getChildCount() - 1);
            this.f3635o = linearLayout;
            this.f3636p = (TextView) linearLayout.findViewById(d.f.f8888e);
            this.f3637q = (TextView) this.f3635o.findViewById(d.f.f8887d);
            if (this.f3638r != 0) {
                this.f3636p.setTextAppearance(getContext(), this.f3638r);
            }
            if (this.f3639s != 0) {
                this.f3637q.setTextAppearance(getContext(), this.f3639s);
            }
        }
        this.f3636p.setText(this.f3630j);
        this.f3637q.setText(this.f3631k);
        boolean zIsEmpty = TextUtils.isEmpty(this.f3630j);
        boolean zIsEmpty2 = TextUtils.isEmpty(this.f3631k);
        this.f3637q.setVisibility(!zIsEmpty2 ? 0 : 8);
        this.f3635o.setVisibility((zIsEmpty && zIsEmpty2) ? 8 : 0);
        if (this.f3635o.getParent() == null) {
            addView(this.f3635o);
        }
    }

    @Override // androidx.appcompat.widget.AbstractC0227a
    public /* bridge */ /* synthetic */ C0261e0 f(int i3, long j3) {
        return super.f(i3, j3);
    }

    public void g() {
        if (this.f3632l == null) {
            k();
        }
    }

    @Override // android.view.ViewGroup
    protected ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new ViewGroup.MarginLayoutParams(-1, -2);
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new ViewGroup.MarginLayoutParams(getContext(), attributeSet);
    }

    @Override // androidx.appcompat.widget.AbstractC0227a
    public /* bridge */ /* synthetic */ int getAnimatedVisibility() {
        return super.getAnimatedVisibility();
    }

    @Override // androidx.appcompat.widget.AbstractC0227a
    public /* bridge */ /* synthetic */ int getContentHeight() {
        return super.getContentHeight();
    }

    public CharSequence getSubtitle() {
        return this.f3631k;
    }

    public CharSequence getTitle() {
        return this.f3630j;
    }

    public void h(androidx.appcompat.view.b bVar) {
        View view = this.f3632l;
        if (view == null) {
            View viewInflate = LayoutInflater.from(getContext()).inflate(this.f3641u, (ViewGroup) this, false);
            this.f3632l = viewInflate;
            addView(viewInflate);
        } else if (view.getParent() == null) {
            addView(this.f3632l);
        }
        View viewFindViewById = this.f3632l.findViewById(d.f.f8892i);
        this.f3633m = viewFindViewById;
        viewFindViewById.setOnClickListener(new a(bVar));
        androidx.appcompat.view.menu.e eVar = (androidx.appcompat.view.menu.e) bVar.e();
        C0229c c0229c = this.f3951e;
        if (c0229c != null) {
            c0229c.y();
        }
        C0229c c0229c2 = new C0229c(getContext());
        this.f3951e = c0229c2;
        c0229c2.J(true);
        ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(-2, -1);
        eVar.c(this.f3951e, this.f3949c);
        ActionMenuView actionMenuView = (ActionMenuView) this.f3951e.o(this);
        this.f3950d = actionMenuView;
        actionMenuView.setBackground(null);
        addView(this.f3950d, layoutParams);
    }

    public boolean j() {
        return this.f3640t;
    }

    public void k() {
        removeAllViews();
        this.f3634n = null;
        this.f3950d = null;
        this.f3951e = null;
        View view = this.f3633m;
        if (view != null) {
            view.setOnClickListener(null);
        }
    }

    public boolean l() {
        C0229c c0229c = this.f3951e;
        if (c0229c != null) {
            return c0229c.K();
        }
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        C0229c c0229c = this.f3951e;
        if (c0229c != null) {
            c0229c.B();
            this.f3951e.C();
        }
    }

    @Override // androidx.appcompat.widget.AbstractC0227a, android.view.View
    public /* bridge */ /* synthetic */ boolean onHoverEvent(MotionEvent motionEvent) {
        return super.onHoverEvent(motionEvent);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        boolean zB = r0.b(this);
        int paddingRight = zB ? (i5 - i3) - getPaddingRight() : getPaddingLeft();
        int paddingTop = getPaddingTop();
        int paddingTop2 = ((i6 - i4) - getPaddingTop()) - getPaddingBottom();
        View view = this.f3632l;
        if (view != null && view.getVisibility() != 8) {
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) this.f3632l.getLayoutParams();
            int i7 = zB ? marginLayoutParams.rightMargin : marginLayoutParams.leftMargin;
            int i8 = zB ? marginLayoutParams.leftMargin : marginLayoutParams.rightMargin;
            int iD = AbstractC0227a.d(paddingRight, i7, zB);
            paddingRight = AbstractC0227a.d(iD + e(this.f3632l, iD, paddingTop, paddingTop2, zB), i8, zB);
        }
        int iE = paddingRight;
        LinearLayout linearLayout = this.f3635o;
        if (linearLayout != null && this.f3634n == null && linearLayout.getVisibility() != 8) {
            iE += e(this.f3635o, iE, paddingTop, paddingTop2, zB);
        }
        int i9 = iE;
        View view2 = this.f3634n;
        if (view2 != null) {
            e(view2, i9, paddingTop, paddingTop2, zB);
        }
        int paddingLeft = zB ? getPaddingLeft() : (i5 - i3) - getPaddingRight();
        ActionMenuView actionMenuView = this.f3950d;
        if (actionMenuView != null) {
            e(actionMenuView, paddingLeft, paddingTop, paddingTop2, !zB);
        }
    }

    @Override // android.view.View
    protected void onMeasure(int i3, int i4) {
        if (View.MeasureSpec.getMode(i3) != 1073741824) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used with android:layout_width=\"match_parent\" (or fill_parent)");
        }
        if (View.MeasureSpec.getMode(i4) == 0) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used with android:layout_height=\"wrap_content\"");
        }
        int size = View.MeasureSpec.getSize(i3);
        int size2 = this.f3952f;
        if (size2 <= 0) {
            size2 = View.MeasureSpec.getSize(i4);
        }
        int paddingTop = getPaddingTop() + getPaddingBottom();
        int paddingLeft = (size - getPaddingLeft()) - getPaddingRight();
        int iMin = size2 - paddingTop;
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(iMin, Integer.MIN_VALUE);
        View view = this.f3632l;
        if (view != null) {
            int iC = c(view, paddingLeft, iMakeMeasureSpec, 0);
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) this.f3632l.getLayoutParams();
            paddingLeft = iC - (marginLayoutParams.leftMargin + marginLayoutParams.rightMargin);
        }
        ActionMenuView actionMenuView = this.f3950d;
        if (actionMenuView != null && actionMenuView.getParent() == this) {
            paddingLeft = c(this.f3950d, paddingLeft, iMakeMeasureSpec, 0);
        }
        LinearLayout linearLayout = this.f3635o;
        if (linearLayout != null && this.f3634n == null) {
            if (this.f3640t) {
                this.f3635o.measure(View.MeasureSpec.makeMeasureSpec(0, 0), iMakeMeasureSpec);
                int measuredWidth = this.f3635o.getMeasuredWidth();
                boolean z3 = measuredWidth <= paddingLeft;
                if (z3) {
                    paddingLeft -= measuredWidth;
                }
                this.f3635o.setVisibility(z3 ? 0 : 8);
            } else {
                paddingLeft = c(linearLayout, paddingLeft, iMakeMeasureSpec, 0);
            }
        }
        View view2 = this.f3634n;
        if (view2 != null) {
            ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
            int i5 = layoutParams.width;
            int i6 = i5 != -2 ? 1073741824 : Integer.MIN_VALUE;
            if (i5 >= 0) {
                paddingLeft = Math.min(i5, paddingLeft);
            }
            int i7 = layoutParams.height;
            int i8 = i7 == -2 ? Integer.MIN_VALUE : 1073741824;
            if (i7 >= 0) {
                iMin = Math.min(i7, iMin);
            }
            this.f3634n.measure(View.MeasureSpec.makeMeasureSpec(paddingLeft, i6), View.MeasureSpec.makeMeasureSpec(iMin, i8));
        }
        if (this.f3952f > 0) {
            setMeasuredDimension(size, size2);
            return;
        }
        int childCount = getChildCount();
        int i9 = 0;
        for (int i10 = 0; i10 < childCount; i10++) {
            int measuredHeight = getChildAt(i10).getMeasuredHeight() + paddingTop;
            if (measuredHeight > i9) {
                i9 = measuredHeight;
            }
        }
        setMeasuredDimension(size, i9);
    }

    @Override // androidx.appcompat.widget.AbstractC0227a, android.view.View
    public /* bridge */ /* synthetic */ boolean onTouchEvent(MotionEvent motionEvent) {
        return super.onTouchEvent(motionEvent);
    }

    @Override // androidx.appcompat.widget.AbstractC0227a
    public void setContentHeight(int i3) {
        this.f3952f = i3;
    }

    public void setCustomView(View view) {
        LinearLayout linearLayout;
        View view2 = this.f3634n;
        if (view2 != null) {
            removeView(view2);
        }
        this.f3634n = view;
        if (view != null && (linearLayout = this.f3635o) != null) {
            removeView(linearLayout);
            this.f3635o = null;
        }
        if (view != null) {
            addView(view);
        }
        requestLayout();
    }

    public void setSubtitle(CharSequence charSequence) {
        this.f3631k = charSequence;
        i();
    }

    public void setTitle(CharSequence charSequence) {
        this.f3630j = charSequence;
        i();
        androidx.core.view.V.a0(this, charSequence);
    }

    public void setTitleOptional(boolean z3) {
        if (z3 != this.f3640t) {
            requestLayout();
        }
        this.f3640t = z3;
    }

    @Override // androidx.appcompat.widget.AbstractC0227a, android.view.View
    public /* bridge */ /* synthetic */ void setVisibility(int i3) {
        super.setVisibility(i3);
    }

    @Override // android.view.ViewGroup
    public boolean shouldDelayChildPressedState() {
        return false;
    }

    public ActionBarContextView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8795g);
    }

    public ActionBarContextView(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        g0 g0VarU = g0.u(context, attributeSet, d.j.f9138y, i3, 0);
        setBackground(g0VarU.f(d.j.f9142z));
        this.f3638r = g0VarU.m(d.j.f8957D, 0);
        this.f3639s = g0VarU.m(d.j.f8953C, 0);
        this.f3952f = g0VarU.l(d.j.f8949B, 0);
        this.f3641u = g0VarU.m(d.j.f8945A, d.g.f8913d);
        g0VarU.w();
    }
}
