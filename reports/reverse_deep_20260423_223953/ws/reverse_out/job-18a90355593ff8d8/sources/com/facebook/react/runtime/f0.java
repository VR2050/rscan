package com.facebook.react.runtime;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewParent;
import c2.C0353a;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.config.ReactFeatureFlags;
import com.facebook.react.uimanager.events.EventDispatcher;
import java.util.Objects;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class f0 extends c1.W {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private static final a f7303A = new a(null);

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final e0 f7304u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final com.facebook.react.uimanager.S f7305v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private com.facebook.react.uimanager.Q f7306w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private boolean f7307x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private int f7308y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private int f7309z;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f0(Context context, e0 e0Var) {
        super(context);
        t2.j.f(e0Var, "surface");
        this.f7304u = e0Var;
        this.f7305v = new com.facebook.react.uimanager.S(this);
        if (ReactFeatureFlags.dispatchPointerEvents) {
            this.f7306w = new com.facebook.react.uimanager.Q(this);
        }
    }

    private final Point getViewportOffset() {
        int[] iArr = new int[2];
        getLocationOnScreen(iArr);
        Rect rect = new Rect();
        getWindowVisibleDisplayFrame(rect);
        iArr[0] = iArr[0] - rect.left;
        iArr[1] = iArr[1] - rect.top;
        return new Point(iArr[0], iArr[1]);
    }

    @Override // c1.W, com.facebook.react.uimanager.InterfaceC0477w0
    public void b(View view, MotionEvent motionEvent) {
        t2.j.f(view, "childView");
        t2.j.f(motionEvent, "ev");
        EventDispatcher eventDispatcherI = this.f7304u.i();
        if (eventDispatcherI == null) {
            return;
        }
        this.f7305v.e(motionEvent, eventDispatcherI);
        com.facebook.react.uimanager.Q q3 = this.f7306w;
        if (q3 != null) {
            q3.o();
        }
    }

    @Override // c1.W, com.facebook.react.uimanager.InterfaceC0477w0
    public void c(View view, MotionEvent motionEvent) {
        com.facebook.react.uimanager.Q q3;
        t2.j.f(motionEvent, "ev");
        EventDispatcher eventDispatcherI = this.f7304u.i();
        if (eventDispatcherI == null) {
            return;
        }
        this.f7305v.f(motionEvent, eventDispatcherI);
        if (view == null || (q3 = this.f7306w) == null) {
            return;
        }
        q3.p(view, motionEvent, eventDispatcherI);
    }

    @Override // c1.W
    protected void f(MotionEvent motionEvent, boolean z3) {
        t2.j.f(motionEvent, "event");
        if (this.f7306w == null) {
            if (ReactFeatureFlags.dispatchPointerEvents) {
                Y.a.I("ReactSurfaceView", "Unable to dispatch pointer events to JS before the dispatcher is available");
                return;
            }
            return;
        }
        EventDispatcher eventDispatcherI = this.f7304u.i();
        if (eventDispatcherI == null) {
            Y.a.I("ReactSurfaceView", "Unable to dispatch pointer events to JS as the React instance has not been attached");
            return;
        }
        com.facebook.react.uimanager.Q q3 = this.f7306w;
        if (q3 != null) {
            q3.k(motionEvent, eventDispatcherI, z3);
        }
    }

    @Override // c1.W
    protected void g(MotionEvent motionEvent) {
        t2.j.f(motionEvent, "event");
        EventDispatcher eventDispatcherI = this.f7304u.i();
        if (eventDispatcherI != null) {
            this.f7305v.c(motionEvent, eventDispatcherI, this.f7304u.l().f0());
        } else {
            Y.a.I("ReactSurfaceView", "Unable to dispatch touch events to JS as the React instance has not been attached");
        }
    }

    @Override // c1.W
    public ReactContext getCurrentReactContext() {
        if (this.f7304u.o()) {
            return this.f7304u.l().f0();
        }
        return null;
    }

    @Override // c1.W, com.facebook.react.uimanager.InterfaceC0462o0
    public String getJSModuleName() {
        String strJ = this.f7304u.j();
        t2.j.e(strJ, "<get-moduleName>(...)");
        return strJ;
    }

    @Override // c1.W, com.facebook.react.uimanager.InterfaceC0462o0
    public int getUIManagerType() {
        return 2;
    }

    @Override // c1.W
    public void h(Throwable th) {
        t2.j.f(th, "t");
        ReactHostImpl reactHostImplL = this.f7304u.l();
        t2.j.e(reactHostImplL, "getReactHost(...)");
        String string = Objects.toString(th.getMessage(), "");
        t2.j.c(string);
        reactHostImplL.y0(new com.facebook.react.uimanager.P(string, this, th));
    }

    @Override // c1.W
    public boolean i() {
        return this.f7304u.o() && this.f7304u.l().f0() != null;
    }

    @Override // c1.W
    public boolean j() {
        return this.f7304u.o() && this.f7304u.l().A0();
    }

    @Override // c1.W
    public boolean o() {
        return this.f7304u.o();
    }

    @Override // c1.W, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        if (this.f7307x && z3) {
            Point viewportOffset = getViewportOffset();
            this.f7304u.s(this.f7308y, this.f7309z, viewportOffset.x, viewportOffset.y);
        }
    }

    @Override // c1.W, android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i3, int i4) {
        int size;
        int size2;
        C0353a.c(0L, "ReactSurfaceView.onMeasure");
        int mode = View.MeasureSpec.getMode(i3);
        if (mode == Integer.MIN_VALUE || mode == 0) {
            int childCount = getChildCount();
            int iMax = 0;
            for (int i5 = 0; i5 < childCount; i5++) {
                View childAt = getChildAt(i5);
                iMax = Math.max(iMax, childAt.getLeft() + childAt.getMeasuredWidth() + childAt.getPaddingLeft() + childAt.getPaddingRight());
            }
            size = iMax;
        } else {
            size = View.MeasureSpec.getSize(i3);
        }
        int mode2 = View.MeasureSpec.getMode(i4);
        if (mode2 == Integer.MIN_VALUE || mode2 == 0) {
            int childCount2 = getChildCount();
            int iMax2 = 0;
            for (int i6 = 0; i6 < childCount2; i6++) {
                View childAt2 = getChildAt(i6);
                iMax2 = Math.max(iMax2, childAt2.getTop() + childAt2.getMeasuredHeight() + childAt2.getPaddingTop() + childAt2.getPaddingBottom());
            }
            size2 = iMax2;
        } else {
            size2 = View.MeasureSpec.getSize(i4);
        }
        setMeasuredDimension(size, size2);
        this.f7307x = true;
        this.f7308y = i3;
        this.f7309z = i4;
        Point viewportOffset = getViewportOffset();
        this.f7304u.s(i3, i4, viewportOffset.x, viewportOffset.y);
        C0353a.i(0L);
    }

    @Override // c1.W, android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean z3) {
        ViewParent parent = getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(z3);
        }
    }

    @Override // c1.W
    public void setIsFabric(boolean z3) {
        super.setIsFabric(true);
    }
}
