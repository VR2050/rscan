package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.C0261e0;
import androidx.core.view.InterfaceC0263f0;
import d.AbstractC0502a;

/* JADX INFO: renamed from: androidx.appcompat.widget.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
abstract class AbstractC0227a extends ViewGroup {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected final C0052a f3948b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected final Context f3949c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected ActionMenuView f3950d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected C0229c f3951e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected int f3952f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected C0261e0 f3953g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3954h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f3955i;

    /* JADX INFO: renamed from: androidx.appcompat.widget.a$a, reason: collision with other inner class name */
    protected class C0052a implements InterfaceC0263f0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f3956a = false;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f3957b;

        protected C0052a() {
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void a(View view) {
            this.f3956a = true;
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            if (this.f3956a) {
                return;
            }
            AbstractC0227a abstractC0227a = AbstractC0227a.this;
            abstractC0227a.f3953g = null;
            AbstractC0227a.super.setVisibility(this.f3957b);
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void c(View view) {
            AbstractC0227a.super.setVisibility(0);
            this.f3956a = false;
        }

        public C0052a d(C0261e0 c0261e0, int i3) {
            AbstractC0227a.this.f3953g = c0261e0;
            this.f3957b = i3;
            return this;
        }
    }

    AbstractC0227a(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        this.f3948b = new C0052a();
        TypedValue typedValue = new TypedValue();
        if (!context.getTheme().resolveAttribute(AbstractC0502a.f8789a, typedValue, true) || typedValue.resourceId == 0) {
            this.f3949c = context;
        } else {
            this.f3949c = new ContextThemeWrapper(context, typedValue.resourceId);
        }
    }

    protected static int d(int i3, int i4, boolean z3) {
        return z3 ? i3 - i4 : i3 + i4;
    }

    protected int c(View view, int i3, int i4, int i5) {
        view.measure(View.MeasureSpec.makeMeasureSpec(i3, Integer.MIN_VALUE), i4);
        return Math.max(0, (i3 - view.getMeasuredWidth()) - i5);
    }

    protected int e(View view, int i3, int i4, int i5, boolean z3) {
        int measuredWidth = view.getMeasuredWidth();
        int measuredHeight = view.getMeasuredHeight();
        int i6 = i4 + ((i5 - measuredHeight) / 2);
        if (z3) {
            view.layout(i3 - measuredWidth, i6, i3, measuredHeight + i6);
        } else {
            view.layout(i3, i6, i3 + measuredWidth, measuredHeight + i6);
        }
        return z3 ? -measuredWidth : measuredWidth;
    }

    public C0261e0 f(int i3, long j3) {
        C0261e0 c0261e0 = this.f3953g;
        if (c0261e0 != null) {
            c0261e0.c();
        }
        if (i3 != 0) {
            C0261e0 c0261e0B = androidx.core.view.V.c(this).b(0.0f);
            c0261e0B.f(j3);
            c0261e0B.h(this.f3948b.d(c0261e0B, i3));
            return c0261e0B;
        }
        if (getVisibility() != 0) {
            setAlpha(0.0f);
        }
        C0261e0 c0261e0B2 = androidx.core.view.V.c(this).b(1.0f);
        c0261e0B2.f(j3);
        c0261e0B2.h(this.f3948b.d(c0261e0B2, i3));
        return c0261e0B2;
    }

    public int getAnimatedVisibility() {
        return this.f3953g != null ? this.f3948b.f3957b : getVisibility();
    }

    public int getContentHeight() {
        return this.f3952f;
    }

    @Override // android.view.View
    protected void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(null, d.j.f9042a, AbstractC0502a.f8791c, 0);
        setContentHeight(typedArrayObtainStyledAttributes.getLayoutDimension(d.j.f9078j, 0));
        typedArrayObtainStyledAttributes.recycle();
        C0229c c0229c = this.f3951e;
        if (c0229c != null) {
            c0229c.F(configuration);
        }
    }

    @Override // android.view.View
    public boolean onHoverEvent(MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 9) {
            this.f3955i = false;
        }
        if (!this.f3955i) {
            boolean zOnHoverEvent = super.onHoverEvent(motionEvent);
            if (actionMasked == 9 && !zOnHoverEvent) {
                this.f3955i = true;
            }
        }
        if (actionMasked == 10 || actionMasked == 3) {
            this.f3955i = false;
        }
        return true;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            this.f3954h = false;
        }
        if (!this.f3954h) {
            boolean zOnTouchEvent = super.onTouchEvent(motionEvent);
            if (actionMasked == 0 && !zOnTouchEvent) {
                this.f3954h = true;
            }
        }
        if (actionMasked == 1 || actionMasked == 3) {
            this.f3954h = false;
        }
        return true;
    }

    public abstract void setContentHeight(int i3);

    @Override // android.view.View
    public void setVisibility(int i3) {
        if (i3 != getVisibility()) {
            C0261e0 c0261e0 = this.f3953g;
            if (c0261e0 != null) {
                c0261e0.c();
            }
            super.setVisibility(i3);
        }
    }
}
