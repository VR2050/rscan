package androidx.appcompat.view.menu;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import androidx.appcompat.view.menu.e;
import androidx.appcompat.view.menu.k;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.D;
import androidx.appcompat.widget.S;
import androidx.appcompat.widget.l0;

/* JADX INFO: loaded from: classes.dex */
public class ActionMenuItemView extends D implements k.a, View.OnClickListener, ActionMenuView.a {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    g f3393i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private CharSequence f3394j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Drawable f3395k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    e.b f3396l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private S f3397m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    b f3398n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f3399o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f3400p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f3401q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f3402r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f3403s;

    private class a extends S {
        public a() {
            super(ActionMenuItemView.this);
        }

        @Override // androidx.appcompat.widget.S
        public i.e b() {
            b bVar = ActionMenuItemView.this.f3398n;
            if (bVar != null) {
                return bVar.a();
            }
            return null;
        }

        @Override // androidx.appcompat.widget.S
        protected boolean c() {
            i.e eVarB;
            ActionMenuItemView actionMenuItemView = ActionMenuItemView.this;
            e.b bVar = actionMenuItemView.f3396l;
            return bVar != null && bVar.a(actionMenuItemView.f3393i) && (eVarB = b()) != null && eVarB.a();
        }
    }

    public static abstract class b {
        public abstract i.e a();
    }

    public ActionMenuItemView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    private boolean u() {
        Configuration configuration = getContext().getResources().getConfiguration();
        int i3 = configuration.screenWidthDp;
        return i3 >= 480 || (i3 >= 640 && configuration.screenHeightDp >= 480) || configuration.orientation == 2;
    }

    private void v() {
        boolean z3 = true;
        boolean z4 = !TextUtils.isEmpty(this.f3394j);
        if (this.f3395k != null && (!this.f3393i.B() || (!this.f3399o && !this.f3400p))) {
            z3 = false;
        }
        boolean z5 = z4 & z3;
        setText(z5 ? this.f3394j : null);
        CharSequence contentDescription = this.f3393i.getContentDescription();
        if (TextUtils.isEmpty(contentDescription)) {
            setContentDescription(z5 ? null : this.f3393i.getTitle());
        } else {
            setContentDescription(contentDescription);
        }
        CharSequence tooltipText = this.f3393i.getTooltipText();
        if (TextUtils.isEmpty(tooltipText)) {
            l0.a(this, z5 ? null : this.f3393i.getTitle());
        } else {
            l0.a(this, tooltipText);
        }
    }

    @Override // androidx.appcompat.view.menu.k.a
    public boolean a() {
        return true;
    }

    @Override // androidx.appcompat.widget.ActionMenuView.a
    public boolean b() {
        return t();
    }

    @Override // androidx.appcompat.widget.ActionMenuView.a
    public boolean d() {
        return t() && this.f3393i.getIcon() == null;
    }

    @Override // androidx.appcompat.view.menu.k.a
    public void e(g gVar, int i3) {
        this.f3393i = gVar;
        setIcon(gVar.getIcon());
        setTitle(gVar.i(this));
        setId(gVar.getItemId());
        setVisibility(gVar.isVisible() ? 0 : 8);
        setEnabled(gVar.isEnabled());
        if (gVar.hasSubMenu() && this.f3397m == null) {
            this.f3397m = new a();
        }
    }

    @Override // android.widget.TextView, android.view.View
    public CharSequence getAccessibilityClassName() {
        return Button.class.getName();
    }

    @Override // androidx.appcompat.view.menu.k.a
    public g getItemData() {
        return this.f3393i;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        e.b bVar = this.f3396l;
        if (bVar != null) {
            bVar.a(this.f3393i);
        }
    }

    @Override // android.widget.TextView, android.view.View
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.f3399o = u();
        v();
    }

    @Override // androidx.appcompat.widget.D, android.widget.TextView, android.view.View
    protected void onMeasure(int i3, int i4) {
        int i5;
        boolean zT = t();
        if (zT && (i5 = this.f3402r) >= 0) {
            super.setPadding(i5, getPaddingTop(), getPaddingRight(), getPaddingBottom());
        }
        super.onMeasure(i3, i4);
        int mode = View.MeasureSpec.getMode(i3);
        int size = View.MeasureSpec.getSize(i3);
        int measuredWidth = getMeasuredWidth();
        int iMin = mode == Integer.MIN_VALUE ? Math.min(size, this.f3401q) : this.f3401q;
        if (mode != 1073741824 && this.f3401q > 0 && measuredWidth < iMin) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(iMin, 1073741824), i4);
        }
        if (zT || this.f3395k == null) {
            return;
        }
        super.setPadding((getMeasuredWidth() - this.f3395k.getBounds().width()) / 2, getPaddingTop(), getPaddingRight(), getPaddingBottom());
    }

    @Override // android.widget.TextView, android.view.View
    public void onRestoreInstanceState(Parcelable parcelable) {
        super.onRestoreInstanceState(null);
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        S s3;
        if (this.f3393i.hasSubMenu() && (s3 = this.f3397m) != null && s3.onTouch(this, motionEvent)) {
            return true;
        }
        return super.onTouchEvent(motionEvent);
    }

    public void setCheckable(boolean z3) {
    }

    public void setChecked(boolean z3) {
    }

    public void setExpandedFormat(boolean z3) {
        if (this.f3400p != z3) {
            this.f3400p = z3;
            g gVar = this.f3393i;
            if (gVar != null) {
                gVar.c();
            }
        }
    }

    public void setIcon(Drawable drawable) {
        this.f3395k = drawable;
        if (drawable != null) {
            int intrinsicWidth = drawable.getIntrinsicWidth();
            int intrinsicHeight = drawable.getIntrinsicHeight();
            int i3 = this.f3403s;
            if (intrinsicWidth > i3) {
                intrinsicHeight = (int) (intrinsicHeight * (i3 / intrinsicWidth));
                intrinsicWidth = i3;
            }
            if (intrinsicHeight > i3) {
                intrinsicWidth = (int) (intrinsicWidth * (i3 / intrinsicHeight));
            } else {
                i3 = intrinsicHeight;
            }
            drawable.setBounds(0, 0, intrinsicWidth, i3);
        }
        setCompoundDrawables(drawable, null, null, null);
        v();
    }

    public void setItemInvoker(e.b bVar) {
        this.f3396l = bVar;
    }

    @Override // android.widget.TextView, android.view.View
    public void setPadding(int i3, int i4, int i5, int i6) {
        this.f3402r = i3;
        super.setPadding(i3, i4, i5, i6);
    }

    public void setPopupCallback(b bVar) {
        this.f3398n = bVar;
    }

    public void setTitle(CharSequence charSequence) {
        this.f3394j = charSequence;
        v();
    }

    public boolean t() {
        return !TextUtils.isEmpty(getText());
    }

    public ActionMenuItemView(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        Resources resources = context.getResources();
        this.f3399o = u();
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, d.j.f9126v, i3, 0);
        this.f3401q = typedArrayObtainStyledAttributes.getDimensionPixelSize(d.j.f9130w, 0);
        typedArrayObtainStyledAttributes.recycle();
        this.f3403s = (int) ((resources.getDisplayMetrics().density * 32.0f) + 0.5f);
        setOnClickListener(this);
        this.f3402r = -1;
        setSaveEnabled(false);
    }
}
