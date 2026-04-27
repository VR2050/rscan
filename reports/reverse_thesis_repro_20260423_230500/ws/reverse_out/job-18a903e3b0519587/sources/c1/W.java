package c1;

import android.content.Context;
import android.graphics.BlendMode;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.DisplayCutout;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.FrameLayout;
import c2.C0353a;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.CatalystInstance;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.config.ReactFeatureFlags;
import com.facebook.react.modules.appregistry.AppRegistry;
import com.facebook.react.modules.deviceinfo.DeviceInfoModule;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0464p0;
import com.facebook.react.uimanager.C0476w;
import com.facebook.react.uimanager.C0478x;
import com.facebook.react.uimanager.C0479x0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.InterfaceC0462o0;
import com.facebook.react.uimanager.InterfaceC0477w0;
import com.facebook.react.uimanager.events.EventDispatcher;
import java.util.concurrent.atomic.AtomicInteger;
import q1.C0655b;

/* JADX INFO: loaded from: classes.dex */
public class W extends FrameLayout implements InterfaceC0477w0, InterfaceC0462o0 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private G f5520b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private String f5521c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Bundle f5522d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private a f5523e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f5524f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f5525g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f5526h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private com.facebook.react.uimanager.S f5527i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private com.facebook.react.uimanager.Q f5528j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final C0348u f5529k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f5530l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f5531m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f5532n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f5533o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f5534p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f5535q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f5536r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f5537s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final AtomicInteger f5538t;

    private class a implements ViewTreeObserver.OnGlobalLayoutListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Rect f5539b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f5540c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f5541d = false;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f5542e = 0;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private int f5543f = 0;

        a() {
            C0478x.f(W.this.getContext().getApplicationContext());
            this.f5539b = new Rect();
            this.f5540c = (int) C0444f0.h(60.0f);
        }

        private void a() {
            g();
        }

        private void b() {
            int rotation = ((WindowManager) W.this.getContext().getSystemService("window")).getDefaultDisplay().getRotation();
            if (this.f5543f == rotation) {
                return;
            }
            this.f5543f = rotation;
            C0478x.e(W.this.getContext().getApplicationContext());
            f(rotation);
        }

        private void c() {
            boolean zIsVisible;
            W.this.getRootView().getWindowVisibleDisplayFrame(this.f5539b);
            WindowInsets rootWindowInsets = W.this.getRootView().getRootWindowInsets();
            if (rootWindowInsets == null || (zIsVisible = rootWindowInsets.isVisible(WindowInsets.Type.ime())) == this.f5541d) {
                return;
            }
            this.f5541d = zIsVisible;
            if (!zIsVisible) {
                W.this.r("keyboardDidHide", e(C0444f0.f(this.f5539b.height()), 0.0d, C0444f0.f(this.f5539b.width()), 0.0d));
                return;
            }
            int i3 = rootWindowInsets.getInsets(WindowInsets.Type.ime()).bottom - rootWindowInsets.getInsets(WindowInsets.Type.systemBars()).bottom;
            ViewGroup.LayoutParams layoutParams = W.this.getRootView().getLayoutParams();
            Z0.a.a(layoutParams instanceof WindowManager.LayoutParams);
            W.this.r("keyboardDidShow", e(C0444f0.f(((WindowManager.LayoutParams) layoutParams).softInputMode == 48 ? this.f5539b.bottom - i3 : this.f5539b.bottom), C0444f0.f(this.f5539b.left), C0444f0.f(this.f5539b.width()), C0444f0.f(i3)));
        }

        private void d() {
            WindowInsets rootWindowInsets;
            DisplayCutout displayCutout;
            W.this.getRootView().getWindowVisibleDisplayFrame(this.f5539b);
            int safeInsetTop = (Build.VERSION.SDK_INT < 28 || (rootWindowInsets = W.this.getRootView().getRootWindowInsets()) == null || (displayCutout = rootWindowInsets.getDisplayCutout()) == null) ? 0 : displayCutout.getSafeInsetTop();
            int i3 = (C0478x.d().heightPixels - this.f5539b.bottom) + safeInsetTop;
            int i4 = this.f5542e;
            if (i4 != i3 && i3 > this.f5540c) {
                this.f5542e = i3;
                this.f5541d = true;
                W.this.r("keyboardDidShow", e(C0444f0.f(r4), C0444f0.f(this.f5539b.left), C0444f0.f(this.f5539b.width()), C0444f0.f(this.f5542e)));
            } else {
                if (i4 == 0 || i3 > this.f5540c) {
                    return;
                }
                this.f5542e = 0;
                this.f5541d = false;
                W.this.r("keyboardDidHide", e(C0444f0.f(r3.height()), 0.0d, C0444f0.f(this.f5539b.width()), 0.0d));
            }
        }

        private WritableMap e(double d3, double d4, double d5, double d6) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            WritableMap writableMapCreateMap2 = Arguments.createMap();
            writableMapCreateMap2.putDouble("height", d6);
            writableMapCreateMap2.putDouble("screenX", d4);
            writableMapCreateMap2.putDouble("width", d5);
            writableMapCreateMap2.putDouble("screenY", d3);
            writableMapCreateMap.putMap("endCoordinates", writableMapCreateMap2);
            writableMapCreateMap.putString("easing", "keyboard");
            writableMapCreateMap.putDouble("duration", 0.0d);
            return writableMapCreateMap;
        }

        private void f(int i3) {
            String str;
            double d3;
            boolean z3 = false;
            if (i3 != 0) {
                if (i3 == 1) {
                    str = "landscape-primary";
                    d3 = -90.0d;
                } else if (i3 == 2) {
                    str = "portrait-secondary";
                    d3 = 180.0d;
                } else {
                    if (i3 != 3) {
                        return;
                    }
                    str = "landscape-secondary";
                    d3 = 90.0d;
                }
                z3 = true;
            } else {
                str = "portrait-primary";
                d3 = 0.0d;
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putString("name", str);
            writableMapCreateMap.putDouble("rotationDegrees", d3);
            writableMapCreateMap.putBoolean("isLandscape", z3);
            W.this.r("namedOrientationDidChange", writableMapCreateMap);
        }

        private void g() {
            DeviceInfoModule deviceInfoModule;
            ReactContext currentReactContext = W.this.getCurrentReactContext();
            if (currentReactContext == null || (deviceInfoModule = (DeviceInfoModule) currentReactContext.getNativeModule(DeviceInfoModule.class)) == null) {
                return;
            }
            deviceInfoModule.emitUpdateDimensionsEvent();
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            if (W.this.i() && W.this.o()) {
                if (Build.VERSION.SDK_INT >= 30) {
                    c();
                } else {
                    d();
                }
                b();
                a();
            }
        }
    }

    public interface b {
    }

    public W(Context context) {
        super(context);
        this.f5524f = 0;
        this.f5529k = new C0348u(this);
        this.f5530l = false;
        this.f5531m = View.MeasureSpec.makeMeasureSpec(0, 0);
        this.f5532n = View.MeasureSpec.makeMeasureSpec(0, 0);
        this.f5533o = 0;
        this.f5534p = 0;
        this.f5535q = Integer.MIN_VALUE;
        this.f5536r = Integer.MIN_VALUE;
        this.f5537s = 1;
        this.f5538t = new AtomicInteger(0);
        k();
    }

    private void e() {
        C0353a.c(0L, "attachToReactInstanceManager");
        ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_ATTACH_TO_REACT_INSTANCE_MANAGER_START);
        if (getId() != -1) {
            ReactSoftExceptionLogger.logSoftException("ReactRootView", new com.facebook.react.uimanager.P("Trying to attach a ReactRootView with an explicit id already set to [" + getId() + "]. React Native uses the id field to track react tags and will overwrite this field. If that is fine, explicitly overwrite the id field to View.NO_ID."));
        }
        try {
            if (this.f5525g) {
                return;
            }
            this.f5525g = true;
            ((G) Z0.a.c(this.f5520b)).s(this);
            getViewTreeObserver().addOnGlobalLayoutListener(getCustomGlobalLayoutListener());
        } finally {
            ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_ATTACH_TO_REACT_INSTANCE_MANAGER_END);
            C0353a.i(0L);
        }
    }

    private a getCustomGlobalLayoutListener() {
        if (this.f5523e == null) {
            this.f5523e = new a();
        }
        return this.f5523e;
    }

    private void k() {
        setRootViewTag(C0464p0.a());
        setClipChildren(false);
    }

    private boolean l() {
        if (!i() || !o()) {
            Y.a.I("ReactRootView", "Unable to dispatch touch to JS as the catalyst instance has not been attached");
            return false;
        }
        if (this.f5527i == null) {
            Y.a.I("ReactRootView", "Unable to dispatch touch to JS before the dispatcher is available");
            return false;
        }
        if (!ReactFeatureFlags.dispatchPointerEvents || this.f5528j != null) {
            return true;
        }
        Y.a.I("ReactRootView", "Unable to dispatch pointer events to JS before the dispatcher is available");
        return false;
    }

    private boolean m() {
        return getUIManagerType() == 2;
    }

    private boolean n() {
        int i3 = this.f5524f;
        return (i3 == 0 || i3 == -1) ? false : true;
    }

    private void q() {
        getViewTreeObserver().removeOnGlobalLayoutListener(getCustomGlobalLayoutListener());
    }

    private void s() {
        DisplayMetrics displayMetrics = getContext().getResources().getDisplayMetrics();
        this.f5531m = View.MeasureSpec.makeMeasureSpec(displayMetrics.widthPixels, Integer.MIN_VALUE);
        this.f5532n = View.MeasureSpec.makeMeasureSpec(displayMetrics.heightPixels, Integer.MIN_VALUE);
    }

    private void w(boolean z3, int i3, int i4) {
        UIManager uIManagerG;
        int i5;
        int i6;
        ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_UPDATE_LAYOUT_SPECS_START);
        if (!j()) {
            ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_UPDATE_LAYOUT_SPECS_END);
            Y.a.I("ReactRootView", "Unable to update root layout specs for uninitialized ReactInstanceManager");
            return;
        }
        boolean zM = m();
        if (zM && !n()) {
            ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_UPDATE_LAYOUT_SPECS_END);
            Y.a.m("ReactRootView", "Unable to update root layout specs for ReactRootView: no rootViewTag set yet");
            return;
        }
        ReactContext currentReactContext = getCurrentReactContext();
        if (currentReactContext != null && (uIManagerG = H0.g(currentReactContext, getUIManagerType())) != null) {
            if (zM) {
                Point pointB = C0479x0.b(this);
                i5 = pointB.x;
                i6 = pointB.y;
            } else {
                i5 = 0;
                i6 = 0;
            }
            if (z3 || i5 != this.f5535q || i6 != this.f5536r) {
                uIManagerG.updateRootLayoutSpecs(getRootViewTag(), i3, i4, i5, i6);
            }
            this.f5535q = i5;
            this.f5536r = i6;
        }
        ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_UPDATE_LAYOUT_SPECS_END);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public void a(int i3) {
        if (i3 != 101) {
            return;
        }
        p();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0477w0
    public void b(View view, MotionEvent motionEvent) {
        EventDispatcher eventDispatcherB;
        if (l() && (eventDispatcherB = H0.b(getCurrentReactContext(), getUIManagerType())) != null) {
            this.f5527i.e(motionEvent, eventDispatcherB);
            com.facebook.react.uimanager.Q q3 = this.f5528j;
            if (q3 != null) {
                q3.o();
            }
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0477w0
    public void c(View view, MotionEvent motionEvent) {
        EventDispatcher eventDispatcherB;
        com.facebook.react.uimanager.Q q3;
        if (l() && (eventDispatcherB = H0.b(getCurrentReactContext(), getUIManagerType())) != null) {
            this.f5527i.f(motionEvent, eventDispatcherB);
            if (view == null || (q3 = this.f5528j) == null) {
                return;
            }
            q3.p(view, motionEvent, eventDispatcherB);
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public void d() {
        C0353a.c(0L, "ReactRootView.runApplication");
        try {
            if (j() && o()) {
                ReactContext currentReactContext = getCurrentReactContext();
                if (currentReactContext == null) {
                    C0353a.i(0L);
                    return;
                }
                CatalystInstance catalystInstance = currentReactContext.getCatalystInstance();
                String jSModuleName = getJSModuleName();
                if (this.f5530l) {
                    w(true, this.f5531m, this.f5532n);
                }
                WritableNativeMap writableNativeMap = new WritableNativeMap();
                writableNativeMap.putDouble("rootTag", getRootViewTag());
                Bundle appProperties = getAppProperties();
                if (appProperties != null) {
                    writableNativeMap.putMap("initialProps", Arguments.fromBundle(appProperties));
                }
                this.f5526h = true;
                ((AppRegistry) catalystInstance.getJSModule(AppRegistry.class)).runApplication(jSModuleName, writableNativeMap);
                C0353a.i(0L);
            }
        } finally {
            C0353a.i(0L);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        try {
            super.dispatchDraw(canvas);
        } catch (StackOverflowError e3) {
            h(e3);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        if (i() && o()) {
            this.f5529k.d(keyEvent);
            return super.dispatchKeyEvent(keyEvent);
        }
        Y.a.I("ReactRootView", "Unable to handle key event as the catalyst instance has not been attached");
        return super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View view, long j3) {
        BlendMode blendModeA;
        if (Build.VERSION.SDK_INT >= 29 && L1.a.c(this) == 2 && C0476w.a(this)) {
            blendModeA = S.a(view.getTag(AbstractC0339k.f5594r));
            if (blendModeA != null) {
                Paint paint = new Paint();
                paint.setBlendMode(blendModeA);
                canvas.saveLayer(0.0f, 0.0f, getWidth(), getHeight(), paint);
            }
        } else {
            blendModeA = null;
        }
        boolean zDrawChild = super.drawChild(canvas, view, j3);
        if (blendModeA != null) {
            canvas.restore();
        }
        return zDrawChild;
    }

    protected void f(MotionEvent motionEvent, boolean z3) {
        if (!i() || !o()) {
            Y.a.I("ReactRootView", "Unable to dispatch touch to JS as the catalyst instance has not been attached");
            return;
        }
        if (this.f5528j == null) {
            if (ReactFeatureFlags.dispatchPointerEvents) {
                Y.a.I("ReactRootView", "Unable to dispatch pointer events to JS before the dispatcher is available");
            }
        } else {
            EventDispatcher eventDispatcherB = H0.b(getCurrentReactContext(), getUIManagerType());
            if (eventDispatcherB != null) {
                this.f5528j.k(motionEvent, eventDispatcherB, z3);
            }
        }
    }

    protected void finalize() throws Throwable {
        super.finalize();
        Z0.a.b(!this.f5525g, "The application this ReactRootView was rendering was not unmounted before the ReactRootView was garbage collected. This usually means that your application is leaking large amounts of memory. To solve this, make sure to call ReactRootView#unmountReactApplication in the onDestroy() of your hosting Activity or in the onDestroyView() of your hosting Fragment.");
    }

    protected void g(MotionEvent motionEvent) {
        if (!i() || !o()) {
            Y.a.I("ReactRootView", "Unable to dispatch touch to JS as the catalyst instance has not been attached");
            return;
        }
        if (this.f5527i == null) {
            Y.a.I("ReactRootView", "Unable to dispatch touch to JS before the dispatcher is available");
            return;
        }
        EventDispatcher eventDispatcherB = H0.b(getCurrentReactContext(), getUIManagerType());
        if (eventDispatcherB != null) {
            this.f5527i.c(motionEvent, eventDispatcherB, getCurrentReactContext());
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public Bundle getAppProperties() {
        return this.f5522d;
    }

    public ReactContext getCurrentReactContext() {
        G g3 = this.f5520b;
        if (g3 == null) {
            return null;
        }
        return g3.C();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public int getHeightMeasureSpec() {
        return this.f5532n;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public String getJSModuleName() {
        return (String) Z0.a.c(this.f5521c);
    }

    public G getReactInstanceManager() {
        return this.f5520b;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public int getRootViewTag() {
        return this.f5524f;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public AtomicInteger getState() {
        return this.f5538t;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public String getSurfaceID() {
        Bundle appProperties = getAppProperties();
        if (appProperties != null) {
            return appProperties.getString("surfaceID");
        }
        return null;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public int getUIManagerType() {
        return this.f5537s;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public int getWidthMeasureSpec() {
        return this.f5531m;
    }

    public void h(Throwable th) {
        if (!i()) {
            throw new RuntimeException(th);
        }
        getCurrentReactContext().handleException(new com.facebook.react.uimanager.P(th.getMessage(), this, th));
    }

    public boolean i() {
        G g3 = this.f5520b;
        return (g3 == null || g3.C() == null) ? false : true;
    }

    public boolean j() {
        return this.f5520b != null;
    }

    public boolean o() {
        return this.f5525g;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (o()) {
            q();
            getViewTreeObserver().addOnGlobalLayoutListener(getCustomGlobalLayoutListener());
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (o()) {
            q();
        }
    }

    @Override // android.view.View
    protected void onFocusChanged(boolean z3, int i3, Rect rect) {
        if (i() && o()) {
            this.f5529k.a();
            super.onFocusChanged(z3, i3, rect);
        } else {
            Y.a.I("ReactRootView", "Unable to handle focus changed event as the catalyst instance has not been attached");
            super.onFocusChanged(z3, i3, rect);
        }
    }

    @Override // android.view.View
    public boolean onHoverEvent(MotionEvent motionEvent) {
        f(motionEvent, false);
        return super.onHoverEvent(motionEvent);
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptHoverEvent(MotionEvent motionEvent) {
        f(motionEvent, true);
        return super.onInterceptHoverEvent(motionEvent);
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (t(motionEvent)) {
            g(motionEvent);
        }
        f(motionEvent, true);
        return super.onInterceptTouchEvent(motionEvent);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        if (this.f5530l && m()) {
            w(false, this.f5531m, this.f5532n);
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i3, int i4) {
        int iMax;
        int iMax2;
        C0353a.c(0L, "ReactRootView.onMeasure");
        ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_ON_MEASURE_START);
        try {
            boolean z3 = (i3 == this.f5531m && i4 == this.f5532n) ? false : true;
            this.f5531m = i3;
            this.f5532n = i4;
            int mode = View.MeasureSpec.getMode(i3);
            if (mode == Integer.MIN_VALUE || mode == 0) {
                iMax = 0;
                for (int i5 = 0; i5 < getChildCount(); i5++) {
                    View childAt = getChildAt(i5);
                    iMax = Math.max(iMax, childAt.getLeft() + childAt.getMeasuredWidth() + childAt.getPaddingLeft() + childAt.getPaddingRight());
                }
            } else {
                iMax = View.MeasureSpec.getSize(i3);
            }
            int mode2 = View.MeasureSpec.getMode(i4);
            if (mode2 == Integer.MIN_VALUE || mode2 == 0) {
                iMax2 = 0;
                for (int i6 = 0; i6 < getChildCount(); i6++) {
                    View childAt2 = getChildAt(i6);
                    iMax2 = Math.max(iMax2, childAt2.getTop() + childAt2.getMeasuredHeight() + childAt2.getPaddingTop() + childAt2.getPaddingBottom());
                }
            } else {
                iMax2 = View.MeasureSpec.getSize(i4);
            }
            setMeasuredDimension(iMax, iMax2);
            this.f5530l = true;
            if (j() && !o()) {
                e();
            } else if (z3 || this.f5533o != iMax || this.f5534p != iMax2) {
                w(true, this.f5531m, this.f5532n);
            }
            this.f5533o = iMax;
            this.f5534p = iMax2;
            ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_ON_MEASURE_END);
            C0353a.i(0L);
        } catch (Throwable th) {
            ReactMarker.logMarker(ReactMarkerConstants.ROOT_VIEW_ON_MEASURE_END);
            C0353a.i(0L);
            throw th;
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (t(motionEvent)) {
            g(motionEvent);
        }
        f(motionEvent, false);
        super.onTouchEvent(motionEvent);
        return true;
    }

    @Override // android.view.ViewGroup
    public void onViewAdded(View view) {
        super.onViewAdded(view);
        if (this.f5526h) {
            this.f5526h = false;
            ReactMarker.logMarker(ReactMarkerConstants.CONTENT_APPEARED, getJSModuleName(), this.f5524f);
        }
    }

    public void p() {
        this.f5527i = new com.facebook.react.uimanager.S(this);
        if (ReactFeatureFlags.dispatchPointerEvents) {
            this.f5528j = new com.facebook.react.uimanager.Q(this);
        }
    }

    void r(String str, WritableMap writableMap) {
        if (j()) {
            getCurrentReactContext().emitDeviceEvent(str, writableMap);
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestChildFocus(View view, View view2) {
        if (i() && o()) {
            this.f5529k.e(view2);
            super.requestChildFocus(view, view2);
        } else {
            Y.a.I("ReactRootView", "Unable to handle child focus changed event as the catalyst instance has not been attached");
            super.requestChildFocus(view, view2);
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean z3) {
        if (getParent() != null) {
            getParent().requestDisallowInterceptTouchEvent(z3);
        }
    }

    public void setAppProperties(Bundle bundle) {
        UiThreadUtil.assertOnUiThread();
        this.f5522d = bundle;
        if (n()) {
            d();
        }
    }

    public void setIsFabric(boolean z3) {
        this.f5537s = z3 ? 2 : 1;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public void setRootViewTag(int i3) {
        this.f5524f = i3;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public void setShouldLogContentAppeared(boolean z3) {
        this.f5526h = z3;
    }

    public boolean t(MotionEvent motionEvent) {
        return true;
    }

    public void u(G g3, String str, Bundle bundle) {
        C0353a.c(0L, "startReactApplication");
        try {
            UiThreadUtil.assertOnUiThread();
            Z0.a.b(this.f5520b == null, "This root view has already been attached to a catalyst instance manager");
            this.f5520b = g3;
            this.f5521c = str;
            this.f5522d = bundle;
            g3.y();
            if (C0655b.d()) {
                if (!this.f5530l) {
                    s();
                }
                e();
            }
            C0353a.i(0L);
        } catch (Throwable th) {
            C0353a.i(0L);
            throw th;
        }
    }

    public void v() {
        UiThreadUtil.assertOnUiThread();
        G g3 = this.f5520b;
        if (g3 != null && this.f5525g) {
            g3.A(this);
            this.f5525g = false;
        }
        this.f5520b = null;
        this.f5526h = false;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0462o0
    public ViewGroup getRootViewGroup() {
        return this;
    }

    public void setEventListener(b bVar) {
    }
}
