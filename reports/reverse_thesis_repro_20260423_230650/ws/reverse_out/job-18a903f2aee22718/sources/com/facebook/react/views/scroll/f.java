package com.facebook.react.views.scroll;

import Q1.p;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.HorizontalScrollView;
import android.widget.OverScroller;
import androidx.core.view.V;
import c1.AbstractC0339k;
import c2.C0353a;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.AbstractC0452j0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.EnumC0446g0;
import com.facebook.react.uimanager.InterfaceC0450i0;
import com.facebook.react.uimanager.InterfaceC0458m0;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.uimanager.Z;
import com.facebook.react.views.scroll.b;
import com.facebook.react.views.scroll.j;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class f extends HorizontalScrollView implements InterfaceC0450i0, ViewGroup.OnHierarchyChangeListener, View.OnLayoutChangeListener, d, InterfaceC0458m0, j.c, j.e, j.a, j.b, j.d {

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private static boolean f7895K = false;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private static String f7896L = "f";

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private static int f7897M = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private static Field f7898N = null;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private static boolean f7899O = false;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private int f7900A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private A0 f7901B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final j.g f7902C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final ValueAnimator f7903D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private EnumC0446g0 f7904E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private long f7905F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private int f7906G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private View f7907H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private com.facebook.react.views.scroll.b f7908I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private final Rect f7909J;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f7910b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final c f7911c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final OverScroller f7912d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final m f7913e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Rect f7914f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f7915g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Rect f7916h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private p f7917i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f7918j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f7919k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Runnable f7920l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f7921m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f7922n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f7923o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private String f7924p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Drawable f7925q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f7926r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f7927s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private int f7928t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private List f7929u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f7930v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f7931w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f7932x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private boolean f7933y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private int f7934z;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f7935b = false;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f7936c = 0;

        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            NativeAnimatedModule nativeAnimatedModule;
            if (f.this.f7915g) {
                f.this.f7915g = false;
                this.f7936c = 0;
                V.T(f.this, this, 20L);
                return;
            }
            j.s(f.this);
            int i3 = this.f7936c + 1;
            this.f7936c = i3;
            if (i3 < 3) {
                if (f.this.f7919k && !this.f7935b) {
                    this.f7935b = true;
                    f.this.w(0);
                }
                V.T(f.this, this, 20L);
                return;
            }
            f.this.f7920l = null;
            if (f.this.f7923o) {
                j.j(f.this);
            }
            ReactContext reactContext = (ReactContext) f.this.getContext();
            if (reactContext != null && (nativeAnimatedModule = (NativeAnimatedModule) reactContext.getNativeModule(NativeAnimatedModule.class)) != null) {
                nativeAnimatedModule.userDrivenScrollEnded(f.this.getId());
            }
            f.this.r();
        }
    }

    static /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f7938a;

        static {
            int[] iArr = new int[p.values().length];
            f7938a = iArr;
            try {
                iArr[p.f2500d.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f7938a[p.f2501e.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f7938a[p.f2499c.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public f(Context context, com.facebook.react.views.scroll.a aVar) {
        super(context);
        this.f7910b = f7897M;
        this.f7911c = new c();
        this.f7913e = new m();
        this.f7914f = new Rect();
        this.f7917i = p.f2501e;
        this.f7919k = false;
        this.f7922n = true;
        this.f7926r = 0;
        this.f7927s = false;
        this.f7928t = 0;
        this.f7930v = true;
        this.f7931w = true;
        this.f7932x = 0;
        this.f7933y = false;
        this.f7934z = -1;
        this.f7900A = -1;
        this.f7901B = null;
        this.f7903D = ObjectAnimator.ofInt(this, "scrollX", 0, 0);
        this.f7904E = EnumC0446g0.f7609f;
        this.f7905F = 0L;
        this.f7906G = 0;
        this.f7909J = new Rect();
        V.X(this, new h());
        this.f7912d = getOverScrollerFromParent();
        this.f7902C = new j.g();
        setOnHierarchyChangeListener(this);
        setClipChildren(false);
    }

    private void B(int i3, int i4) {
        if (f7895K) {
            Y.a.u(f7896L, "handlePostTouchScrolling[%d] velocityX %d velocityY %d", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        if (this.f7920l != null) {
            return;
        }
        if (this.f7923o) {
            j.i(this, i3, i4);
        }
        this.f7915g = false;
        a aVar = new a();
        this.f7920l = aVar;
        V.T(this, aVar, 20L);
    }

    private boolean C() {
        View contentView = getContentView();
        return (contentView == null || contentView.getWidth() == 0 || contentView.getHeight() == 0) ? false : true;
    }

    private boolean D(View view) {
        int iZ = z(view);
        view.getDrawingRect(this.f7909J);
        return iZ != 0 && Math.abs(iZ) < this.f7909J.width() / 2;
    }

    private boolean E() {
        return false;
    }

    private boolean F(View view) {
        return z(view) == 0;
    }

    private int G(int i3) {
        int iMax = Math.max(0, computeHorizontalScrollRange() - getWidth());
        if (getFlingAnimator() == this.f7903D) {
            return j.p(this, i3, 0, iMax, 0).x;
        }
        return x(i3) + j.m(this, getScrollX(), getReactScrollViewScrollState().b().x, i3);
    }

    private void H(int i3, int i4) {
        if (getFlingAnimator().isRunning()) {
            getFlingAnimator().cancel();
        }
        OverScroller overScroller = this.f7912d;
        if (overScroller == null || overScroller.isFinished()) {
            return;
        }
        int currX = this.f7912d.getCurrX();
        boolean zComputeScrollOffset = this.f7912d.computeScrollOffset();
        this.f7912d.forceFinished(true);
        if (!zComputeScrollOffset) {
            scrollTo(i3 + (this.f7912d.getCurrX() - currX), getScrollY());
            return;
        }
        this.f7912d.fling(i3, getScrollY(), (int) (this.f7912d.getCurrVelocity() * Math.signum(this.f7912d.getFinalX() - this.f7912d.getStartX())), 0, 0, i4, 0, 0);
    }

    private void I(View view) {
        int iZ = z(view);
        if (iZ != 0) {
            scrollBy(iZ, 0);
        }
    }

    private void K(int i3, int i4) {
        if (f7895K) {
            Y.a.u(f7896L, "setPendingContentOffsets[%d] x %d y %d", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        if (C()) {
            this.f7934z = -1;
            this.f7900A = -1;
        } else {
            this.f7934z = i3;
            this.f7900A = i4;
        }
    }

    private void L(int i3) {
        if (f7895K) {
            Y.a.t(f7896L, "smoothScrollAndSnap[%d] velocity %d", Integer.valueOf(getId()), Integer.valueOf(i3));
        }
        double snapInterval = getSnapInterval();
        double dM = j.m(this, getScrollX(), getReactScrollViewScrollState().b().x, i3);
        double dG = G(i3);
        double d3 = dM / snapInterval;
        int iFloor = (int) Math.floor(d3);
        int iCeil = (int) Math.ceil(d3);
        int iRound = (int) Math.round(d3);
        int iRound2 = (int) Math.round(dG / snapInterval);
        if (i3 > 0 && iCeil == iFloor) {
            iCeil++;
        } else if (i3 < 0 && iFloor == iCeil) {
            iFloor--;
        }
        if (i3 > 0 && iRound < iCeil && iRound2 > iFloor) {
            iRound = iCeil;
        } else if (i3 < 0 && iRound > iFloor && iRound2 < iCeil) {
            iRound = iFloor;
        }
        double d4 = ((double) iRound) * snapInterval;
        if (d4 != dM) {
            this.f7915g = true;
            f((int) d4, getScrollY());
        }
    }

    private void M(int i3) {
        if (f7895K) {
            Y.a.t(f7896L, "smoothScrollToNextPage[%d] direction %d", Integer.valueOf(getId()), Integer.valueOf(i3));
        }
        int width = getWidth();
        int scrollX = getScrollX();
        int i4 = scrollX / width;
        if (scrollX % width != 0) {
            i4++;
        }
        int i5 = i3 == 17 ? i4 - 1 : i4 + 1;
        if (i5 < 0) {
            i5 = 0;
        }
        f(i5 * width, getScrollY());
        B(0, 0);
    }

    private View getContentView() {
        return getChildAt(0);
    }

    private OverScroller getOverScrollerFromParent() {
        if (!f7899O) {
            f7899O = true;
            try {
                Field declaredField = HorizontalScrollView.class.getDeclaredField("mScroller");
                f7898N = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException unused) {
                Y.a.I(f7896L, "Failed to get mScroller field for HorizontalScrollView! This app will exhibit the bounce-back scrolling bug :(");
            }
        }
        Field field = f7898N;
        OverScroller overScroller = null;
        if (field != null) {
            try {
                Object obj = field.get(this);
                if (obj instanceof OverScroller) {
                    overScroller = (OverScroller) obj;
                } else {
                    Y.a.I(f7896L, "Failed to cast mScroller field in HorizontalScrollView (probably due to OEM changes to AOSP)! This app will exhibit the bounce-back scrolling bug :(");
                }
            } catch (IllegalAccessException e3) {
                throw new RuntimeException("Failed to get mScroller from HorizontalScrollView!", e3);
            }
        }
        return overScroller;
    }

    private int getSnapInterval() {
        int i3 = this.f7928t;
        return i3 != 0 ? i3 : getWidth();
    }

    private void p(int i3, int i4, int i5, int i6) {
        if (getFlingAnimator().isRunning()) {
            getFlingAnimator().end();
        }
        int i7 = i4 - i3;
        int scrollX = i7 - (i6 - getScrollX());
        scrollTo(scrollX, getScrollY());
        H(scrollX, i7 - getWidth());
    }

    private void q() {
        Runnable runnable = this.f7920l;
        if (runnable != null) {
            removeCallbacks(runnable);
            this.f7920l = null;
            getFlingAnimator().cancel();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void r() {
        if (E()) {
            Z0.a.c(null);
            Z0.a.c(this.f7924p);
            throw null;
        }
    }

    private void s() {
        if (E()) {
            Z0.a.c(null);
            Z0.a.c(this.f7924p);
            throw null;
        }
    }

    private static HorizontalScrollView t(View view, MotionEvent motionEvent) {
        return u(view, motionEvent, true);
    }

    private static HorizontalScrollView u(View view, MotionEvent motionEvent, boolean z3) {
        if (view == null) {
            return null;
        }
        Rect rect = new Rect();
        view.getGlobalVisibleRect(rect);
        if (!rect.contains((int) motionEvent.getRawX(), (int) motionEvent.getRawY())) {
            return null;
        }
        if (!z3 && (view instanceof HorizontalScrollView) && V.G(view) && (view instanceof f) && ((f) view).f7922n) {
            return (HorizontalScrollView) view;
        }
        if (view instanceof ViewGroup) {
            int i3 = 0;
            while (true) {
                ViewGroup viewGroup = (ViewGroup) view;
                if (i3 >= viewGroup.getChildCount()) {
                    break;
                }
                HorizontalScrollView horizontalScrollViewU = u(viewGroup.getChildAt(i3), motionEvent, false);
                if (horizontalScrollViewU != null) {
                    return horizontalScrollViewU;
                }
                i3++;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void w(int i3) {
        int i4;
        int iMin;
        int iIntValue;
        int iMax;
        int iIntValue2;
        OverScroller overScroller;
        if (f7895K) {
            Y.a.t(f7896L, "smoothScrollAndSnap[%d] velocityX %d", Integer.valueOf(getId()), Integer.valueOf(i3));
        }
        if (getChildCount() <= 0) {
            return;
        }
        if (this.f7928t == 0 && this.f7929u == null && this.f7932x == 0) {
            L(i3);
            return;
        }
        boolean z3 = getFlingAnimator() != this.f7903D;
        int iMax2 = Math.max(0, computeHorizontalScrollRange() - getWidth());
        int iG = G(i3);
        if (this.f7927s) {
            iG = getScrollX();
        }
        int width = (getWidth() - V.w(this)) - V.v(this);
        if (getLayoutDirection() == 1) {
            iG = iMax2 - iG;
            i4 = -i3;
        } else {
            i4 = i3;
        }
        List list = this.f7929u;
        if (list == null || list.isEmpty()) {
            int i5 = this.f7932x;
            if (i5 != 0) {
                int i6 = this.f7928t;
                if (i6 > 0) {
                    double d3 = ((double) iG) / ((double) i6);
                    double dFloor = Math.floor(d3);
                    int i7 = this.f7928t;
                    int iMax3 = Math.max(y(i5, (int) (dFloor * ((double) i7)), i7, width), 0);
                    int i8 = this.f7932x;
                    double dCeil = Math.ceil(d3);
                    int i9 = this.f7928t;
                    iMin = Math.min(y(i8, (int) (dCeil * ((double) i9)), i9, width), iMax2);
                    iIntValue = iMax2;
                    iMax = iMax3;
                    iIntValue2 = 0;
                } else {
                    ViewGroup viewGroup = (ViewGroup) getContentView();
                    int iMin2 = iMax2;
                    int i10 = iMin2;
                    int i11 = 0;
                    int iMax4 = 0;
                    for (int i12 = 0; i12 < viewGroup.getChildCount(); i12++) {
                        View childAt = viewGroup.getChildAt(i12);
                        int iY = y(this.f7932x, childAt.getLeft(), childAt.getWidth(), width);
                        if (iY <= iG && iG - iY < iG - i11) {
                            i11 = iY;
                        }
                        if (iY >= iG && iY - iG < i10 - iG) {
                            i10 = iY;
                        }
                        iMin2 = Math.min(iMin2, iY);
                        iMax4 = Math.max(iMax4, iY);
                    }
                    iMax = Math.max(i11, iMin2);
                    iMin = Math.min(i10, iMax4);
                    iIntValue = iMax2;
                }
            } else {
                double snapInterval = getSnapInterval();
                double d4 = ((double) iG) / snapInterval;
                int iFloor = (int) (Math.floor(d4) * snapInterval);
                iMin = Math.min((int) (Math.ceil(d4) * snapInterval), iMax2);
                iIntValue = iMax2;
                iMax = iFloor;
            }
            iIntValue2 = 0;
        } else {
            iIntValue2 = ((Integer) this.f7929u.get(0)).intValue();
            List list2 = this.f7929u;
            iIntValue = ((Integer) list2.get(list2.size() - 1)).intValue();
            iMin = iMax2;
            iMax = 0;
            for (int i13 = 0; i13 < this.f7929u.size(); i13++) {
                int iIntValue3 = ((Integer) this.f7929u.get(i13)).intValue();
                if (iIntValue3 <= iG && iG - iIntValue3 < iG - iMax) {
                    iMax = iIntValue3;
                }
                if (iIntValue3 >= iG && iIntValue3 - iG < iMin - iG) {
                    iMin = iIntValue3;
                }
            }
        }
        int i14 = iG - iMax;
        int i15 = iMin - iG;
        int i16 = Math.abs(i14) < Math.abs(i15) ? iMax : iMin;
        int scrollX = getScrollX();
        if (getLayoutDirection() == 1) {
            scrollX = iMax2 - scrollX;
        }
        if (this.f7931w || iG < iIntValue) {
            if (this.f7930v || iG > iIntValue2) {
                if (i4 > 0) {
                    if (!z3) {
                        i4 += (int) (((double) i15) * 10.0d);
                    }
                    iG = iMin;
                } else if (i4 < 0) {
                    if (!z3) {
                        i4 -= (int) (((double) i14) * 10.0d);
                    }
                    iG = iMax;
                } else {
                    iG = i16;
                }
            } else if (scrollX > iIntValue2) {
                iG = iIntValue2;
            }
        } else if (scrollX < iIntValue) {
            iG = iIntValue;
        }
        int iMin3 = Math.min(Math.max(0, iG), iMax2);
        if (getLayoutDirection() == 1) {
            iMin3 = iMax2 - iMin3;
            i4 = -i4;
        }
        int i17 = iMin3;
        if (z3 || (overScroller = this.f7912d) == null) {
            f(i17, getScrollY());
            return;
        }
        this.f7915g = true;
        overScroller.fling(getScrollX(), getScrollY(), i4 != 0 ? i4 : i17 - getScrollX(), 0, i17, i17, 0, 0, (i17 == 0 || i17 == iMax2) ? width / 2 : 0, 0);
        postInvalidateOnAnimation();
    }

    private int y(int i3, int i4, int i5, int i6) {
        int i7;
        if (i3 == 1) {
            return i4;
        }
        if (i3 == 2) {
            i7 = (i6 - i5) / 2;
        } else {
            if (i3 != 3) {
                throw new IllegalStateException("Invalid SnapToAlignment value: " + this.f7932x);
            }
            i7 = i6 - i5;
        }
        return i4 - i7;
    }

    private int z(View view) {
        view.getDrawingRect(this.f7909J);
        offsetDescendantRectToMyCoords(view, this.f7909J);
        return computeScrollDeltaToGetChildRectOnScreen(this.f7909J);
    }

    protected void A(MotionEvent motionEvent) {
        O1.m.b(this, motionEvent);
        j.d(this);
        this.f7918j = true;
        s();
        getFlingAnimator().cancel();
    }

    public void J(float f3, int i3) {
        C0433a.q(this, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(C0444f0.f(f3), X.f7535b));
    }

    @Override // com.facebook.react.views.scroll.j.a
    public void a(int i3, int i4) {
        this.f7903D.cancel();
        int iL = j.l(getContext());
        this.f7903D.setDuration(iL).setIntValues(i3, i4);
        this.f7903D.start();
        if (this.f7923o) {
            j.i(this, iL > 0 ? (i4 - i3) / iL : 0, 0);
            j.a(this);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void addFocusables(ArrayList arrayList, int i3, int i4) {
        if (!this.f7919k || this.f7933y) {
            super.addFocusables(arrayList, i3, i4);
            return;
        }
        ArrayList<View> arrayList2 = new ArrayList<>();
        super.addFocusables(arrayList2, i3, i4);
        for (View view : arrayList2) {
            if (F(view) || c(view) || view.isFocused()) {
                arrayList.add(view);
            }
        }
    }

    @Override // android.widget.HorizontalScrollView
    public boolean arrowScroll(int i3) {
        if (!this.f7919k) {
            return super.arrowScroll(i3);
        }
        boolean z3 = true;
        this.f7933y = true;
        if (getChildCount() > 0) {
            View viewFindNextFocus = FocusFinder.getInstance().findNextFocus(this, findFocus(), i3);
            View contentView = getContentView();
            if (contentView == null || viewFindNextFocus == null || viewFindNextFocus.getParent() != contentView) {
                M(i3);
            } else {
                if (!F(viewFindNextFocus) && !D(viewFindNextFocus)) {
                    M(i3);
                }
                viewFindNextFocus.requestFocus();
            }
        } else {
            z3 = false;
        }
        this.f7933y = false;
        return z3;
    }

    @Override // com.facebook.react.views.scroll.j.d
    public void b(int i3, int i4) {
        scrollTo(i3, i4);
        H(i3, Integer.MAX_VALUE);
    }

    @Override // com.facebook.react.views.scroll.d
    public boolean c(View view) {
        int iZ = z(view);
        view.getDrawingRect(this.f7909J);
        return iZ != 0 && Math.abs(iZ) < this.f7909J.width();
    }

    @Override // android.view.View
    public boolean canScrollHorizontally(int i3) {
        return this.f7922n && super.canScrollHorizontally(i3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0458m0
    public void d(int i3, int i4, int i5, int i6) {
        this.f7914f.set(i3, i4, i5, i6);
    }

    @Override // android.view.View
    public boolean dispatchGenericMotionEvent(MotionEvent motionEvent) {
        if (EnumC0446g0.c(this.f7904E)) {
            return super.dispatchGenericMotionEvent(motionEvent);
        }
        return false;
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public void draw(Canvas canvas) {
        if (this.f7926r != 0) {
            View contentView = getContentView();
            if (this.f7925q != null && contentView != null && contentView.getRight() < getWidth()) {
                this.f7925q.setBounds(contentView.getRight(), 0, getWidth(), getHeight());
                this.f7925q.draw(canvas);
            }
        }
        super.draw(canvas);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public void e() {
        if (this.f7921m) {
            C0353a.c(0L, "ReactHorizontalScrollView.updateClippingRect");
            try {
                Z0.a.c(this.f7916h);
                AbstractC0452j0.a(this, this.f7916h);
                KeyEvent.Callback contentView = getContentView();
                if (contentView instanceof InterfaceC0450i0) {
                    ((InterfaceC0450i0) contentView).e();
                }
            } finally {
                C0353a.i(0L);
            }
        }
    }

    @Override // android.widget.HorizontalScrollView
    public boolean executeKeyEvent(KeyEvent keyEvent) {
        int keyCode = keyEvent.getKeyCode();
        if (this.f7922n || !(keyCode == 21 || keyCode == 22)) {
            return super.executeKeyEvent(keyEvent);
        }
        return false;
    }

    @Override // com.facebook.react.views.scroll.j.d
    public void f(int i3, int i4) {
        j.r(this, i3, i4);
        K(i3, i4);
    }

    @Override // android.widget.HorizontalScrollView
    public void fling(int i3) {
        if (f7895K) {
            Y.a.t(f7896L, "fling[%d] velocityX %d", Integer.valueOf(getId()), Integer.valueOf(i3));
        }
        if (Build.VERSION.SDK_INT == 28) {
            i3 = (int) (Math.abs(i3) * Math.signum(this.f7911c.a()));
        }
        if (this.f7919k) {
            w(i3);
        } else if (this.f7912d != null) {
            this.f7912d.fling(getScrollX(), getScrollY(), i3, 0, 0, Integer.MAX_VALUE, 0, 0, ((getWidth() - V.w(this)) - V.v(this)) / 2, 0);
            V.R(this);
        } else {
            super.fling(i3);
        }
        B(i3, 0);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public void g(Rect rect) {
        rect.set((Rect) Z0.a.c(this.f7916h));
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean getChildVisibleRect(View view, Rect rect, Point point) {
        return super.getChildVisibleRect(view, rect, point);
    }

    @Override // com.facebook.react.views.scroll.j.a
    public ValueAnimator getFlingAnimator() {
        return this.f7903D;
    }

    @Override // com.facebook.react.views.scroll.j.b
    public long getLastScrollDispatchTime() {
        return this.f7905F;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0456l0
    public String getOverflow() {
        int i3 = b.f7938a[this.f7917i.ordinal()];
        if (i3 == 1) {
            return "hidden";
        }
        if (i3 == 2) {
            return "scroll";
        }
        if (i3 != 3) {
            return null;
        }
        return "visible";
    }

    @Override // com.facebook.react.uimanager.InterfaceC0458m0
    public Rect getOverflowInset() {
        return this.f7914f;
    }

    public EnumC0446g0 getPointerEvents() {
        return this.f7904E;
    }

    @Override // com.facebook.react.views.scroll.j.c
    public j.g getReactScrollViewScrollState() {
        return this.f7902C;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0450i0
    public boolean getRemoveClippedSubviews() {
        return this.f7921m;
    }

    @Override // com.facebook.react.views.scroll.d
    public boolean getScrollEnabled() {
        return this.f7922n;
    }

    @Override // com.facebook.react.views.scroll.j.b
    public int getScrollEventThrottle() {
        return this.f7906G;
    }

    @Override // com.facebook.react.views.scroll.j.e
    public A0 getStateWrapper() {
        return this.f7901B;
    }

    public void o() {
        OverScroller overScroller = this.f7912d;
        if (overScroller == null || overScroller.isFinished()) {
            return;
        }
        this.f7912d.abortAnimation();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.f7921m) {
            e();
        }
        com.facebook.react.views.scroll.b bVar = this.f7908I;
        if (bVar != null) {
            bVar.f();
        }
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public void onChildViewAdded(View view, View view2) {
        this.f7907H = view2;
        view2.addOnLayoutChangeListener(this);
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public void onChildViewRemoved(View view, View view2) {
        View view3 = this.f7907H;
        if (view3 != null) {
            view3.removeOnLayoutChangeListener(this);
        }
        this.f7907H = null;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        com.facebook.react.views.scroll.b bVar = this.f7908I;
        if (bVar != null) {
            bVar.g();
        }
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        if (this.f7917i != p.f2499c) {
            C0433a.a(this, canvas);
        }
        super.onDraw(canvas);
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        String str = (String) getTag(AbstractC0339k.f5596t);
        if (str != null) {
            accessibilityNodeInfo.setViewIdResourceName(str);
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (!this.f7922n) {
            return false;
        }
        if (motionEvent.getAction() == 0 && t(this, motionEvent) != null) {
            return false;
        }
        if (!EnumC0446g0.c(this.f7904E)) {
            return true;
        }
        try {
            if (super.onInterceptTouchEvent(motionEvent)) {
                A(motionEvent);
                return true;
            }
        } catch (IllegalArgumentException e3) {
            Y.a.J("ReactNative", "Error intercepting touch event.", e3);
        }
        return false;
    }

    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        OverScroller overScroller;
        if (f7895K) {
            Y.a.v(f7896L, "onLayout[%d] l %d t %d r %d b %d", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5), Integer.valueOf(i6));
        }
        int i7 = this.f7910b;
        if (i7 != f7897M && (overScroller = this.f7912d) != null && i7 != overScroller.getFinalX() && !this.f7912d.isFinished()) {
            if (f7895K) {
                Y.a.t(f7896L, "onLayout[%d] scroll hack enabled: reset to previous scrollX position of %d", Integer.valueOf(getId()), Integer.valueOf(this.f7910b));
            }
            OverScroller overScroller2 = this.f7912d;
            overScroller2.startScroll(this.f7910b, overScroller2.getFinalY(), 0, 0);
            this.f7912d.forceFinished(true);
            this.f7910b = f7897M;
        }
        if (C()) {
            int scrollX = this.f7934z;
            if (scrollX == -1) {
                scrollX = getScrollX();
            }
            int scrollY = this.f7900A;
            if (scrollY == -1) {
                scrollY = getScrollY();
            }
            scrollTo(scrollX, scrollY);
        }
        j.c(this);
    }

    @Override // android.view.View.OnLayoutChangeListener
    public void onLayoutChange(View view, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        if (this.f7907H == null) {
            return;
        }
        if (view.getLayoutDirection() == 1) {
            p(i3, i5, i7, i9);
        } else {
            com.facebook.react.views.scroll.b bVar = this.f7908I;
            if (bVar != null) {
                bVar.h();
            }
        }
        j.b(this);
    }

    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i3, int i4) {
        OverScroller overScroller;
        Z.a(i3, i4);
        int size = View.MeasureSpec.getSize(i3);
        int size2 = View.MeasureSpec.getSize(i4);
        if (f7895K) {
            Y.a.u(f7896L, "onMeasure[%d] measured width: %d measured height: %d", Integer.valueOf(getId()), Integer.valueOf(size), Integer.valueOf(size2));
        }
        boolean z3 = getMeasuredHeight() != size2;
        setMeasuredDimension(size, size2);
        if (!z3 || (overScroller = this.f7912d) == null) {
            return;
        }
        this.f7910b = overScroller.getCurrX();
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    protected void onOverScrolled(int i3, int i4, boolean z3, boolean z4) {
        int iMax;
        if (f7895K) {
            Y.a.v(f7896L, "onOverScrolled[%d] scrollX %d scrollY %d clampedX %b clampedY %b", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4), Boolean.valueOf(z3), Boolean.valueOf(z4));
        }
        OverScroller overScroller = this.f7912d;
        if (overScroller != null && !overScroller.isFinished() && this.f7912d.getCurrX() != this.f7912d.getFinalX() && i3 >= (iMax = Math.max(computeHorizontalScrollRange() - getWidth(), 0))) {
            this.f7912d.abortAnimation();
            i3 = iMax;
        }
        super.onOverScrolled(i3, i4, z3, z4);
    }

    @Override // android.view.View
    protected void onScrollChanged(int i3, int i4, int i5, int i6) {
        if (f7895K) {
            Y.a.v(f7896L, "onScrollChanged[%d] x %d y %d oldx %d oldy %d", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5), Integer.valueOf(i6));
        }
        C0353a.c(0L, "ReactHorizontalScrollView.onScrollChanged");
        try {
            super.onScrollChanged(i3, i4, i5, i6);
            this.f7915g = true;
            if (this.f7911c.c(i3, i4)) {
                if (this.f7921m) {
                    e();
                }
                j.u(this, this.f7911c.a(), this.f7911c.b());
            }
            C0353a.i(0L);
        } catch (Throwable th) {
            C0353a.i(0L);
            throw th;
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    protected void onSizeChanged(int i3, int i4, int i5, int i6) {
        super.onSizeChanged(i3, i4, i5, i6);
        if (this.f7921m) {
            e();
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (!this.f7922n || !EnumC0446g0.b(this.f7904E)) {
            return false;
        }
        this.f7913e.a(motionEvent);
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 1 && this.f7918j) {
            j.s(this);
            float fB = this.f7913e.b();
            float fC = this.f7913e.c();
            j.e(this, fB, fC);
            O1.m.a(this, motionEvent);
            this.f7918j = false;
            B(Math.round(fB), Math.round(fC));
        }
        if (actionMasked == 0) {
            q();
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // android.widget.HorizontalScrollView
    public boolean pageScroll(int i3) {
        boolean zPageScroll = super.pageScroll(i3);
        if (this.f7919k && zPageScroll) {
            B(0, 0);
        }
        return zPageScroll;
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup, android.view.ViewParent
    public void requestChildFocus(View view, View view2) {
        if (view2 != null && !this.f7919k) {
            I(view2);
        }
        super.requestChildFocus(view, view2);
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public void scrollTo(int i3, int i4) {
        if (f7895K) {
            Y.a.u(f7896L, "scrollTo[%d] x %d y %d", Integer.valueOf(getId()), Integer.valueOf(i3), Integer.valueOf(i4));
        }
        super.scrollTo(i3, i4);
        j.s(this);
        K(i3, i4);
    }

    @Override // android.view.View
    public void setBackgroundColor(int i3) {
        C0433a.n(this, Integer.valueOf(i3));
    }

    public void setBorderRadius(float f3) {
        J(f3, Q1.d.f2402b.ordinal());
    }

    public void setBorderStyle(String str) {
        C0433a.r(this, str == null ? null : Q1.f.b(str));
    }

    public void setDecelerationRate(float f3) {
        getReactScrollViewScrollState().h(f3);
        OverScroller overScroller = this.f7912d;
        if (overScroller != null) {
            overScroller.setFriction(1.0f - f3);
        }
    }

    public void setDisableIntervalMomentum(boolean z3) {
        this.f7927s = z3;
    }

    public void setEndFillColor(int i3) {
        if (i3 != this.f7926r) {
            this.f7926r = i3;
            this.f7925q = new ColorDrawable(this.f7926r);
        }
    }

    @Override // com.facebook.react.views.scroll.j.b
    public void setLastScrollDispatchTime(long j3) {
        this.f7905F = j3;
    }

    public void setMaintainVisibleContentPosition(b.C0118b c0118b) {
        com.facebook.react.views.scroll.b bVar;
        if (c0118b != null && this.f7908I == null) {
            com.facebook.react.views.scroll.b bVar2 = new com.facebook.react.views.scroll.b(this, true);
            this.f7908I = bVar2;
            bVar2.f();
        } else if (c0118b == null && (bVar = this.f7908I) != null) {
            bVar.g();
            this.f7908I = null;
        }
        com.facebook.react.views.scroll.b bVar3 = this.f7908I;
        if (bVar3 != null) {
            bVar3.e(c0118b);
        }
    }

    public void setOverflow(String str) {
        if (str == null) {
            this.f7917i = p.f2501e;
        } else {
            p pVarB = p.b(str);
            if (pVarB == null) {
                pVarB = p.f2501e;
            }
            this.f7917i = pVarB;
        }
        invalidate();
    }

    public void setPagingEnabled(boolean z3) {
        this.f7919k = z3;
    }

    public void setPointerEvents(EnumC0446g0 enumC0446g0) {
        this.f7904E = enumC0446g0;
    }

    public void setRemoveClippedSubviews(boolean z3) {
        if (z3 && this.f7916h == null) {
            this.f7916h = new Rect();
        }
        this.f7921m = z3;
        e();
    }

    public void setScrollEnabled(boolean z3) {
        this.f7922n = z3;
    }

    public void setScrollEventThrottle(int i3) {
        this.f7906G = i3;
    }

    public void setScrollPerfTag(String str) {
        this.f7924p = str;
    }

    public void setSendMomentumEvents(boolean z3) {
        this.f7923o = z3;
    }

    public void setSnapInterval(int i3) {
        this.f7928t = i3;
    }

    public void setSnapOffsets(List<Integer> list) {
        this.f7929u = list;
    }

    public void setSnapToAlignment(int i3) {
        this.f7932x = i3;
    }

    public void setSnapToEnd(boolean z3) {
        this.f7931w = z3;
    }

    public void setSnapToStart(boolean z3) {
        this.f7930v = z3;
    }

    public void setStateWrapper(A0 a02) {
        this.f7901B = a02;
    }

    public void v() {
        awakenScrollBars();
    }

    public int x(int i3) {
        return j.p(this, i3, 0, Math.max(0, computeHorizontalScrollRange() - getWidth()), 0).x;
    }
}
