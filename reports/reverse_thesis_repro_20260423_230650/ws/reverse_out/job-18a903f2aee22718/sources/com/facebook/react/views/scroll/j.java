package com.facebook.react.views.scroll;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Point;
import android.view.View;
import android.view.ViewGroup;
import android.widget.OverScroller;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.events.EventDispatcher;
import i2.AbstractC0586n;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* JADX INFO: loaded from: classes.dex */
public final class j {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final boolean f7987c = false;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static boolean f7991g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final j f7985a = new j();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final String f7986b = com.facebook.react.views.scroll.g.class.getSimpleName();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final CopyOnWriteArrayList f7988d = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final CopyOnWriteArrayList f7989e = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static int f7990f = 250;

    public interface a {
        void a(int i3, int i4);

        ValueAnimator getFlingAnimator();
    }

    public interface b {
        long getLastScrollDispatchTime();

        int getScrollEventThrottle();

        void setLastScrollDispatchTime(long j3);
    }

    public interface c {
        g getReactScrollViewScrollState();
    }

    public interface d {
        void b(int i3, int i4);

        void f(int i3, int i4);
    }

    public interface e {
        A0 getStateWrapper();
    }

    private static final class f extends OverScroller {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f7992a;

        public f(Context context) {
            super(context);
            this.f7992a = 250;
        }

        public final int a() {
            super.startScroll(0, 0, 0, 0);
            return this.f7992a;
        }

        @Override // android.widget.OverScroller
        public void startScroll(int i3, int i4, int i5, int i6, int i7) {
            this.f7992a = i7;
        }
    }

    public static final class g {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f7994b;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f7996d;

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Point f7993a = new Point();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Point f7995c = new Point(-1, -1);

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f7997e = true;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private float f7998f = 0.985f;

        public final float a() {
            return this.f7998f;
        }

        public final Point b() {
            return this.f7993a;
        }

        public final Point c() {
            return this.f7995c;
        }

        public final int d() {
            return this.f7994b;
        }

        public final boolean e() {
            return this.f7996d;
        }

        public final boolean f() {
            return this.f7997e;
        }

        public final void g(boolean z3) {
            this.f7996d = z3;
        }

        public final void h(float f3) {
            this.f7998f = f3;
        }

        public final g i(int i3, int i4) {
            this.f7993a.set(i3, i4);
            return this;
        }

        public final void j(boolean z3) {
            this.f7997e = z3;
        }

        public final g k(int i3, int i4) {
            this.f7995c.set(i3, i4);
            return this;
        }

        public final void l(int i3) {
            this.f7994b = i3;
        }
    }

    public static final class h implements Animator.AnimatorListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ViewGroup f7999a;

        h(ViewGroup viewGroup) {
            this.f7999a = viewGroup;
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
            t2.j.f(animator, "animator");
            j.j(this.f7999a);
            animator.removeListener(this);
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            t2.j.f(animator, "animator");
            j.j(this.f7999a);
            animator.removeListener(this);
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationRepeat(Animator animator) {
            t2.j.f(animator, "animator");
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animator) {
            t2.j.f(animator, "animator");
        }
    }

    public static final class i implements Animator.AnimatorListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ViewGroup f8000a;

        i(ViewGroup viewGroup) {
            this.f8000a = viewGroup;
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
            t2.j.f(animator, "animator");
            ((c) this.f8000a).getReactScrollViewScrollState().g(true);
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            t2.j.f(animator, "animator");
            ((c) this.f8000a).getReactScrollViewScrollState().j(true);
            j.s(this.f8000a);
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationRepeat(Animator animator) {
            t2.j.f(animator, "animator");
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animator) {
            t2.j.f(animator, "animator");
            g reactScrollViewScrollState = ((c) this.f8000a).getReactScrollViewScrollState();
            reactScrollViewScrollState.g(false);
            reactScrollViewScrollState.j(false);
        }
    }

    private j() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void a(ViewGroup viewGroup) {
        ((a) viewGroup).getFlingAnimator().addListener(new h(viewGroup));
    }

    public static final void b(ViewGroup viewGroup) {
        t2.j.f(viewGroup, "scrollView");
        Iterator it = f7989e.iterator();
        t2.j.e(it, "iterator(...)");
        while (it.hasNext()) {
            androidx.activity.result.d.a(((WeakReference) it.next()).get());
        }
    }

    public static final void c(ViewGroup viewGroup) {
        t2.j.f(viewGroup, "scrollView");
        Iterator it = f7988d.iterator();
        t2.j.e(it, "iterator(...)");
        while (it.hasNext()) {
            androidx.activity.result.d.a(((WeakReference) it.next()).get());
        }
    }

    public static final void d(ViewGroup viewGroup) {
        f7985a.g(viewGroup, l.f8015c);
    }

    public static final void e(ViewGroup viewGroup, float f3, float f4) {
        f7985a.h(viewGroup, l.f8016d, f3, f4);
    }

    public static final void f(ViewGroup viewGroup, float f3, float f4) {
        f7985a.h(viewGroup, l.f8017e, f3, f4);
    }

    private final void g(ViewGroup viewGroup, l lVar) {
        h(viewGroup, lVar, 0.0f, 0.0f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final void h(ViewGroup viewGroup, l lVar, float f3, float f4) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (lVar == l.f8017e) {
            if (r1.getScrollEventThrottle() >= Math.max(17L, jCurrentTimeMillis - ((b) viewGroup).getLastScrollDispatchTime())) {
                return;
            }
        }
        View childAt = viewGroup.getChildAt(0);
        if (childAt == null) {
            return;
        }
        Iterator it = AbstractC0586n.T(f7988d).iterator();
        while (it.hasNext()) {
            androidx.activity.result.d.a(((WeakReference) it.next()).get());
        }
        Context context = viewGroup.getContext();
        t2.j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        ReactContext reactContext = (ReactContext) context;
        int iE = H0.e(reactContext);
        EventDispatcher eventDispatcherC = H0.c(reactContext, viewGroup.getId());
        if (eventDispatcherC != null) {
            eventDispatcherC.g(k.f8001r.a(iE, viewGroup.getId(), lVar, viewGroup.getScrollX(), viewGroup.getScrollY(), f3, f4, childAt.getWidth(), childAt.getHeight(), viewGroup.getWidth(), viewGroup.getHeight()));
            if (lVar == l.f8017e) {
                ((b) viewGroup).setLastScrollDispatchTime(jCurrentTimeMillis);
            }
        }
    }

    public static final void i(ViewGroup viewGroup, int i3, int i4) {
        f7985a.h(viewGroup, l.f8018f, i3, i4);
    }

    public static final void j(ViewGroup viewGroup) {
        f7985a.g(viewGroup, l.f8019g);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void k(ViewGroup viewGroup) {
        g reactScrollViewScrollState = ((c) viewGroup).getReactScrollViewScrollState();
        int iD = reactScrollViewScrollState.d();
        Point pointC = reactScrollViewScrollState.c();
        int i3 = pointC.x;
        int i4 = pointC.y;
        if (f7987c) {
            Y.a.u(f7986b, "updateFabricScrollState[%d] scrollX %d scrollY %d", Integer.valueOf(viewGroup.getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        A0 stateWrapper = ((e) viewGroup).getStateWrapper();
        if (stateWrapper != null) {
            WritableNativeMap writableNativeMap = new WritableNativeMap();
            writableNativeMap.putDouble("contentOffsetLeft", C0444f0.f(i3));
            writableNativeMap.putDouble("contentOffsetTop", C0444f0.f(i4));
            writableNativeMap.putDouble("scrollAwayPaddingTop", C0444f0.f(iD));
            stateWrapper.b(writableNativeMap);
        }
    }

    public static final int l(Context context) {
        if (!f7991g) {
            f7991g = true;
            try {
                f7990f = new f(context).a();
            } catch (Throwable unused) {
            }
        }
        return f7990f;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final int m(ViewGroup viewGroup, int i3, int i4, int i5) {
        g reactScrollViewScrollState = ((c) viewGroup).getReactScrollViewScrollState();
        return (!reactScrollViewScrollState.f() || (reactScrollViewScrollState.e() && ((i5 != 0 ? i5 / Math.abs(i5) : 0) * (i4 - i3) > 0))) ? i4 : i3;
    }

    public static final int n(String str) {
        if (str == null) {
            return 1;
        }
        int iHashCode = str.hashCode();
        if (iHashCode != -1414557169) {
            if (iHashCode != 3005871) {
                if (iHashCode == 104712844 && str.equals("never")) {
                    return 2;
                }
            } else if (str.equals("auto")) {
                return 1;
            }
        } else if (str.equals("always")) {
            return 0;
        }
        Y.a.I("ReactNative", "wrong overScrollMode: " + str);
        return 1;
    }

    public static final int o(String str) {
        if (str == null) {
            return 0;
        }
        if (z2.g.j("start", str, true)) {
            return 1;
        }
        if (z2.g.j("center", str, true)) {
            return 2;
        }
        if (t2.j.b("end", str)) {
            return 3;
        }
        Y.a.I("ReactNative", "wrong snap alignment value: " + str);
        return 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final Point p(ViewGroup viewGroup, int i3, int i4, int i5, int i6) {
        g reactScrollViewScrollState = ((c) viewGroup).getReactScrollViewScrollState();
        OverScroller overScroller = new OverScroller(viewGroup.getContext());
        overScroller.setFriction(1.0f - reactScrollViewScrollState.a());
        int width = (viewGroup.getWidth() - viewGroup.getPaddingStart()) - viewGroup.getPaddingEnd();
        int height = (viewGroup.getHeight() - viewGroup.getPaddingBottom()) - viewGroup.getPaddingTop();
        Point pointB = reactScrollViewScrollState.b();
        overScroller.fling(m(viewGroup, viewGroup.getScrollX(), pointB.x, i3), m(viewGroup, viewGroup.getScrollY(), pointB.y, i4), i3, i4, 0, i5, 0, i6, width / 2, height / 2);
        return new Point(overScroller.getFinalX(), overScroller.getFinalY());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void r(ViewGroup viewGroup, int i3, int i4) {
        if (f7987c) {
            Y.a.u(f7986b, "smoothScrollTo[%d] x %d y %d", Integer.valueOf(viewGroup.getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        a aVar = (a) viewGroup;
        ValueAnimator flingAnimator = aVar.getFlingAnimator();
        if (flingAnimator.getListeners() == null || flingAnimator.getListeners().size() == 0) {
            f7985a.q(viewGroup);
        }
        ((c) viewGroup).getReactScrollViewScrollState().i(i3, i4);
        int scrollX = viewGroup.getScrollX();
        int scrollY = viewGroup.getScrollY();
        if (scrollX != i3) {
            aVar.a(scrollX, i3);
        }
        if (scrollY != i4) {
            aVar.a(scrollY, i4);
        }
    }

    public static final void s(ViewGroup viewGroup) {
        f7985a.t(viewGroup, viewGroup.getScrollX(), viewGroup.getScrollY());
    }

    public static final void u(ViewGroup viewGroup, float f3, float f4) {
        f7985a.t(viewGroup, viewGroup.getScrollX(), viewGroup.getScrollY());
        f(viewGroup, f3, f4);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void q(ViewGroup viewGroup) {
        ((a) viewGroup).getFlingAnimator().addListener(new i(viewGroup));
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void t(ViewGroup viewGroup, int i3, int i4) {
        if (f7987c) {
            Y.a.u(f7986b, "updateFabricScrollState[%d] scrollX %d scrollY %d", Integer.valueOf(viewGroup.getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        if (L1.a.a(viewGroup.getId()) == 1) {
            return;
        }
        g reactScrollViewScrollState = ((c) viewGroup).getReactScrollViewScrollState();
        if (reactScrollViewScrollState.c().equals(i3, i4)) {
            return;
        }
        reactScrollViewScrollState.k(i3, i4);
        k(viewGroup);
    }
}
