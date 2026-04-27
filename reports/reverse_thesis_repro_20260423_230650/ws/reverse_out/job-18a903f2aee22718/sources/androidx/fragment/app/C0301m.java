package androidx.fragment.app;

import android.animation.LayoutTransition;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import androidx.core.view.C0271j0;
import androidx.core.view.V;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: renamed from: androidx.fragment.app.m, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0301m extends FrameLayout {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final List f5002b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f5003c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private View.OnApplyWindowInsetsListener f5004d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f5005e;

    /* JADX INFO: renamed from: androidx.fragment.app.m$a */
    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final a f5006a = new a();

        private a() {
        }

        public final WindowInsets a(View.OnApplyWindowInsetsListener onApplyWindowInsetsListener, View view, WindowInsets windowInsets) {
            t2.j.f(onApplyWindowInsetsListener, "onApplyWindowInsetsListener");
            t2.j.f(view, "v");
            t2.j.f(windowInsets, "insets");
            WindowInsets windowInsetsOnApplyWindowInsets = onApplyWindowInsetsListener.onApplyWindowInsets(view, windowInsets);
            t2.j.e(windowInsetsOnApplyWindowInsets, "onApplyWindowInsetsListe…lyWindowInsets(v, insets)");
            return windowInsetsOnApplyWindowInsets;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0301m(Context context, AttributeSet attributeSet, x xVar) {
        String str;
        super(context, attributeSet);
        t2.j.f(context, "context");
        t2.j.f(attributeSet, "attrs");
        t2.j.f(xVar, "fm");
        this.f5002b = new ArrayList();
        this.f5003c = new ArrayList();
        this.f5005e = true;
        String classAttribute = attributeSet.getClassAttribute();
        int[] iArr = A.c.f13e;
        t2.j.e(iArr, "FragmentContainerView");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, iArr, 0, 0);
        classAttribute = classAttribute == null ? typedArrayObtainStyledAttributes.getString(A.c.f14f) : classAttribute;
        String string = typedArrayObtainStyledAttributes.getString(A.c.f15g);
        typedArrayObtainStyledAttributes.recycle();
        int id = getId();
        Fragment fragmentG0 = xVar.g0(id);
        if (classAttribute != null && fragmentG0 == null) {
            if (id == -1) {
                if (string != null) {
                    str = " with tag " + string;
                } else {
                    str = "";
                }
                throw new IllegalStateException("FragmentContainerView must have an android:id to add Fragment " + classAttribute + str);
            }
            Fragment fragmentA = xVar.r0().a(context.getClassLoader(), classAttribute);
            t2.j.e(fragmentA, "fm.fragmentFactory.insta…ontext.classLoader, name)");
            fragmentA.v0(context, attributeSet, null);
            xVar.o().m(true).c(this, fragmentA, string).i();
        }
        xVar.V0(this);
    }

    private final void a(View view) {
        if (this.f5003c.contains(view)) {
            this.f5002b.add(view);
        }
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i3, ViewGroup.LayoutParams layoutParams) {
        t2.j.f(view, "child");
        if (x.A0(view) != null) {
            super.addView(view, i3, layoutParams);
            return;
        }
        throw new IllegalStateException(("Views added to a FragmentContainerView must be associated with a Fragment. View " + view + " is not associated with a Fragment.").toString());
    }

    @Override // android.view.ViewGroup, android.view.View
    public WindowInsets dispatchApplyWindowInsets(WindowInsets windowInsets) {
        C0271j0 c0271j0M;
        t2.j.f(windowInsets, "insets");
        C0271j0 c0271j0V = C0271j0.v(windowInsets);
        t2.j.e(c0271j0V, "toWindowInsetsCompat(insets)");
        View.OnApplyWindowInsetsListener onApplyWindowInsetsListener = this.f5004d;
        if (onApplyWindowInsetsListener != null) {
            a aVar = a.f5006a;
            t2.j.c(onApplyWindowInsetsListener);
            c0271j0M = C0271j0.v(aVar.a(onApplyWindowInsetsListener, this, windowInsets));
        } else {
            c0271j0M = V.M(this, c0271j0V);
        }
        t2.j.e(c0271j0M, "if (applyWindowInsetsLis…, insetsCompat)\n        }");
        if (!c0271j0M.n()) {
            int childCount = getChildCount();
            for (int i3 = 0; i3 < childCount; i3++) {
                V.e(getChildAt(i3), c0271j0M);
            }
        }
        return windowInsets;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        t2.j.f(canvas, "canvas");
        if (this.f5005e) {
            Iterator it = this.f5002b.iterator();
            while (it.hasNext()) {
                super.drawChild(canvas, (View) it.next(), getDrawingTime());
            }
        }
        super.dispatchDraw(canvas);
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View view, long j3) {
        t2.j.f(canvas, "canvas");
        t2.j.f(view, "child");
        if (this.f5005e && !this.f5002b.isEmpty() && this.f5002b.contains(view)) {
            return false;
        }
        return super.drawChild(canvas, view, j3);
    }

    @Override // android.view.ViewGroup
    public void endViewTransition(View view) {
        t2.j.f(view, "view");
        this.f5003c.remove(view);
        if (this.f5002b.remove(view)) {
            this.f5005e = true;
        }
        super.endViewTransition(view);
    }

    public final <F extends Fragment> F getFragment() {
        return (F) x.j0(this).g0(getId());
    }

    @Override // android.view.View
    public WindowInsets onApplyWindowInsets(WindowInsets windowInsets) {
        t2.j.f(windowInsets, "insets");
        return windowInsets;
    }

    @Override // android.view.ViewGroup
    public void removeAllViewsInLayout() {
        int childCount = getChildCount();
        while (true) {
            childCount--;
            if (-1 >= childCount) {
                super.removeAllViewsInLayout();
                return;
            } else {
                View childAt = getChildAt(childCount);
                t2.j.e(childAt, "view");
                a(childAt);
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public void removeView(View view) {
        t2.j.f(view, "view");
        a(view);
        super.removeView(view);
    }

    @Override // android.view.ViewGroup
    public void removeViewAt(int i3) {
        View childAt = getChildAt(i3);
        t2.j.e(childAt, "view");
        a(childAt);
        super.removeViewAt(i3);
    }

    @Override // android.view.ViewGroup
    public void removeViewInLayout(View view) {
        t2.j.f(view, "view");
        a(view);
        super.removeViewInLayout(view);
    }

    @Override // android.view.ViewGroup
    public void removeViews(int i3, int i4) {
        int i5 = i3 + i4;
        for (int i6 = i3; i6 < i5; i6++) {
            View childAt = getChildAt(i6);
            t2.j.e(childAt, "view");
            a(childAt);
        }
        super.removeViews(i3, i4);
    }

    @Override // android.view.ViewGroup
    public void removeViewsInLayout(int i3, int i4) {
        int i5 = i3 + i4;
        for (int i6 = i3; i6 < i5; i6++) {
            View childAt = getChildAt(i6);
            t2.j.e(childAt, "view");
            a(childAt);
        }
        super.removeViewsInLayout(i3, i4);
    }

    public final void setDrawDisappearingViewsLast(boolean z3) {
        this.f5005e = z3;
    }

    @Override // android.view.ViewGroup
    public void setLayoutTransition(LayoutTransition layoutTransition) {
        throw new UnsupportedOperationException("FragmentContainerView does not support Layout Transitions or animateLayoutChanges=\"true\".");
    }

    @Override // android.view.View
    public void setOnApplyWindowInsetsListener(View.OnApplyWindowInsetsListener onApplyWindowInsetsListener) {
        t2.j.f(onApplyWindowInsetsListener, "listener");
        this.f5004d = onApplyWindowInsetsListener;
    }

    @Override // android.view.ViewGroup
    public void startViewTransition(View view) {
        t2.j.f(view, "view");
        if (view.getParent() == this) {
            this.f5003c.add(view);
        }
        super.startViewTransition(view);
    }
}
