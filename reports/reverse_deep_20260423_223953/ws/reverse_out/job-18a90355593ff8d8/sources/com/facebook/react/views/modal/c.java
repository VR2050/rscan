package com.facebook.react.views.modal;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Build;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewStructure;
import android.view.Window;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import androidx.core.view.C0271j0;
import androidx.core.view.I0;
import c1.AbstractC0339k;
import c1.AbstractC0343o;
import com.facebook.react.bridge.GuardedRunnable;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.config.ReactFeatureFlags;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.InterfaceC0477w0;
import com.facebook.react.uimanager.Q;
import com.facebook.react.uimanager.S;
import com.facebook.react.uimanager.UIManagerModule;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.views.view.g;
import com.facebook.react.views.view.p;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c extends ViewGroup implements LifecycleEventListener {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final a f7843l = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Dialog f7844b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f7845c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private DialogInterface.OnShowListener f7846d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private InterfaceC0116c f7847e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f7848f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f7849g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private String f7850h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f7851i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final b f7852j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f7853k;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public static final class b extends g implements InterfaceC0477w0 {

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        private A0 f7854t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        private EventDispatcher f7855u;

        /* JADX INFO: renamed from: v, reason: collision with root package name */
        private int f7856v;

        /* JADX INFO: renamed from: w, reason: collision with root package name */
        private int f7857w;

        /* JADX INFO: renamed from: x, reason: collision with root package name */
        private final S f7858x;

        /* JADX INFO: renamed from: y, reason: collision with root package name */
        private Q f7859y;

        public static final class a extends GuardedRunnable {
            a(B0 b02) {
                super(b02);
            }

            @Override // com.facebook.react.bridge.GuardedRunnable
            public void runGuarded() {
                UIManagerModule uIManagerModule = (UIManagerModule) b.this.getReactContext().b().getNativeModule(UIManagerModule.class);
                if (uIManagerModule != null) {
                    uIManagerModule.updateNodeSize(b.this.getId(), b.this.f7856v, b.this.f7857w);
                }
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(Context context) {
            super(context);
            j.f(context, "context");
            this.f7858x = new S(this);
            if (ReactFeatureFlags.dispatchPointerEvents) {
                this.f7859y = new Q(this);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final B0 getReactContext() {
            Context context = getContext();
            j.d(context, "null cannot be cast to non-null type com.facebook.react.uimanager.ThemedReactContext");
            return (B0) context;
        }

        public final void I(int i3, int i4) {
            C0444f0 c0444f0 = C0444f0.f7603a;
            float fD = c0444f0.d(i3);
            float fD2 = c0444f0.d(i4);
            A0 a02 = this.f7854t;
            if (a02 == null) {
                getReactContext().runOnNativeModulesQueueThread(new a(getReactContext()));
                return;
            }
            WritableNativeMap writableNativeMap = new WritableNativeMap();
            writableNativeMap.putDouble("screenWidth", fD);
            writableNativeMap.putDouble("screenHeight", fD2);
            a02.b(writableNativeMap);
        }

        @Override // com.facebook.react.uimanager.InterfaceC0477w0
        public void b(View view, MotionEvent motionEvent) {
            j.f(view, "childView");
            j.f(motionEvent, "ev");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null) {
                this.f7858x.e(motionEvent, eventDispatcher);
            }
            Q q3 = this.f7859y;
            if (q3 != null) {
                q3.o();
            }
        }

        @Override // com.facebook.react.uimanager.InterfaceC0477w0
        public void c(View view, MotionEvent motionEvent) {
            j.f(motionEvent, "ev");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null) {
                this.f7858x.f(motionEvent, eventDispatcher);
                Q q3 = this.f7859y;
                if (q3 != null) {
                    q3.p(view, motionEvent, eventDispatcher);
                }
            }
        }

        public final EventDispatcher getEventDispatcher$ReactAndroid_release() {
            return this.f7855u;
        }

        public final A0 getStateWrapper$ReactAndroid_release() {
            return this.f7854t;
        }

        @Override // com.facebook.react.views.view.g, android.view.View
        public boolean onHoverEvent(MotionEvent motionEvent) {
            Q q3;
            j.f(motionEvent, "event");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null && (q3 = this.f7859y) != null) {
                q3.k(motionEvent, eventDispatcher, false);
            }
            return super.onHoverEvent(motionEvent);
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
            j.f(accessibilityNodeInfo, "info");
            super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
            String str = (String) getTag(AbstractC0339k.f5596t);
            if (str != null) {
                accessibilityNodeInfo.setViewIdResourceName(str);
            }
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptHoverEvent(MotionEvent motionEvent) {
            Q q3;
            j.f(motionEvent, "event");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null && (q3 = this.f7859y) != null) {
                q3.k(motionEvent, eventDispatcher, true);
            }
            return super.onHoverEvent(motionEvent);
        }

        @Override // com.facebook.react.views.view.g, android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
            j.f(motionEvent, "event");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null) {
                this.f7858x.c(motionEvent, eventDispatcher, getReactContext());
                Q q3 = this.f7859y;
                if (q3 != null) {
                    q3.k(motionEvent, eventDispatcher, true);
                }
            }
            return super.onInterceptTouchEvent(motionEvent);
        }

        @Override // com.facebook.react.views.view.g, android.view.View
        protected void onSizeChanged(int i3, int i4, int i5, int i6) {
            super.onSizeChanged(i3, i4, i5, i6);
            this.f7856v = i3;
            this.f7857w = i4;
            I(i3, i4);
        }

        @Override // com.facebook.react.views.view.g, android.view.View
        public boolean onTouchEvent(MotionEvent motionEvent) {
            j.f(motionEvent, "event");
            EventDispatcher eventDispatcher = this.f7855u;
            if (eventDispatcher != null) {
                this.f7858x.c(motionEvent, eventDispatcher, getReactContext());
                Q q3 = this.f7859y;
                if (q3 != null) {
                    q3.k(motionEvent, eventDispatcher, false);
                }
            }
            super.onTouchEvent(motionEvent);
            return true;
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean z3) {
        }

        public final void setEventDispatcher$ReactAndroid_release(EventDispatcher eventDispatcher) {
            this.f7855u = eventDispatcher;
        }

        public final void setStateWrapper$ReactAndroid_release(A0 a02) {
            this.f7854t = a02;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.views.modal.c$c, reason: collision with other inner class name */
    public interface InterfaceC0116c {
        void a(DialogInterface dialogInterface);
    }

    public static final class d implements DialogInterface.OnKeyListener {
        d() {
        }

        @Override // android.content.DialogInterface.OnKeyListener
        public boolean onKey(DialogInterface dialogInterface, int i3, KeyEvent keyEvent) {
            j.f(dialogInterface, "dialog");
            j.f(keyEvent, "event");
            if (keyEvent.getAction() != 1) {
                return false;
            }
            if (i3 == 4 || i3 == 111) {
                InterfaceC0116c onRequestCloseListener = c.this.getOnRequestCloseListener();
                if (onRequestCloseListener == null) {
                    throw new IllegalStateException("onRequestClose callback must be set if back key is expected to close the modal");
                }
                onRequestCloseListener.a(dialogInterface);
                return true;
            }
            Context context = c.this.getContext();
            j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
            Activity currentActivity = ((ReactContext) context).getCurrentActivity();
            if (currentActivity != null) {
                return currentActivity.onKeyUp(i3, keyEvent);
            }
            return false;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(B0 b02) {
        super(b02);
        j.f(b02, "context");
        this.f7852j = new b(b02);
    }

    private final void a() {
        Activity activity;
        UiThreadUtil.assertOnUiThread();
        Dialog dialog = this.f7844b;
        if (dialog != null) {
            if (dialog.isShowing() && ((activity = (Activity) U1.a.a(dialog.getContext(), Activity.class)) == null || !activity.isFinishing())) {
                dialog.dismiss();
            }
            this.f7844b = null;
            this.f7853k = true;
            ViewParent parent = this.f7852j.getParent();
            ViewGroup viewGroup = parent instanceof ViewGroup ? (ViewGroup) parent : null;
            if (viewGroup != null) {
                viewGroup.removeViewAt(0);
            }
        }
    }

    private final boolean b(Activity activity) {
        return (activity == null || (activity.getWindow().getAttributes().flags & 8192) == 0) ? false : true;
    }

    private final void e(C0271j0 c0271j0, I0 i02, List list) {
        Iterator it = list.iterator();
        while (it.hasNext()) {
            int iIntValue = ((Number) it.next()).intValue();
            if (c0271j0.o(iIntValue)) {
                if (i02 != null) {
                    i02.e(iIntValue);
                }
            } else if (i02 != null) {
                i02.a(iIntValue);
            }
        }
    }

    static /* synthetic */ void f(c cVar, C0271j0 c0271j0, I0 i02, List list, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            list = AbstractC0586n.i(Integer.valueOf(C0271j0.m.d()), Integer.valueOf(C0271j0.m.c()));
        }
        cVar.e(c0271j0, i02, list);
    }

    private final void g() {
        Dialog dialog = this.f7844b;
        if (dialog == null) {
            throw new IllegalStateException("dialog must exist when we call updateProperties");
        }
        Window window = dialog.getWindow();
        if (window == null) {
            throw new IllegalStateException("dialog must have window when we call updateProperties");
        }
        Activity currentActivity = getCurrentActivity();
        if (currentActivity == null || currentActivity.isFinishing() || currentActivity.isDestroyed()) {
            return;
        }
        try {
            Window window2 = currentActivity.getWindow();
            if (window2 != null) {
                if ((window2.getAttributes().flags & 1024) != 0) {
                    window.addFlags(1024);
                } else {
                    window.clearFlags(1024);
                }
            }
            p.e(window, this.f7849g);
            if (!this.f7849g) {
                p.b(window, this.f7848f);
            }
            if (this.f7845c) {
                window.clearFlags(2);
            } else {
                window.setDimAmount(0.5f);
                window.setFlags(2, 2);
            }
        } catch (IllegalArgumentException e3) {
            Y.a.o("ReactNative", "ReactModalHostView: error while setting window flags: ", e3.getMessage());
        }
    }

    private final View getContentView() {
        FrameLayout frameLayout = new FrameLayout(getContext());
        frameLayout.addView(this.f7852j);
        if (!this.f7848f) {
            frameLayout.setFitsSystemWindows(true);
        }
        return frameLayout;
    }

    private final Activity getCurrentActivity() {
        Context context = getContext();
        j.d(context, "null cannot be cast to non-null type com.facebook.react.uimanager.ThemedReactContext");
        return ((B0) context).getCurrentActivity();
    }

    private final void h() {
        Activity currentActivity = getCurrentActivity();
        if (currentActivity == null) {
            return;
        }
        Dialog dialog = this.f7844b;
        if (dialog == null) {
            throw new IllegalStateException("dialog must exist when we call updateProperties");
        }
        Window window = dialog.getWindow();
        if (window == null) {
            throw new IllegalStateException("dialog must have window when we call updateProperties");
        }
        Window window2 = currentActivity.getWindow();
        if (Build.VERSION.SDK_INT <= 30) {
            window.getDecorView().setSystemUiVisibility(window2.getDecorView().getSystemUiVisibility());
            return;
        }
        I0 i02 = new I0(window2, window2.getDecorView());
        I0 i03 = new I0(window, window.getDecorView());
        i03.d(i02.b());
        WindowInsets rootWindowInsets = window2.getDecorView().getRootWindowInsets();
        if (rootWindowInsets != null) {
            C0271j0 c0271j0V = C0271j0.v(rootWindowInsets);
            j.e(c0271j0V, "toWindowInsetsCompat(...)");
            f(this, c0271j0V, i03, null, 4, null);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void addChildrenForAccessibility(ArrayList arrayList) {
        j.f(arrayList, "outChildren");
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i3) {
        UiThreadUtil.assertOnUiThread();
        this.f7852j.addView(view, i3);
    }

    public final void c() {
        Context context = getContext();
        j.d(context, "null cannot be cast to non-null type com.facebook.react.uimanager.ThemedReactContext");
        ((B0) context).removeLifecycleEventListener(this);
        a();
    }

    public final void d() {
        Window window;
        Window window2;
        UiThreadUtil.assertOnUiThread();
        if (!this.f7853k) {
            g();
            return;
        }
        a();
        this.f7853k = false;
        String str = this.f7850h;
        int i3 = j.b(str, "fade") ? AbstractC0343o.f5652e : j.b(str, "slide") ? AbstractC0343o.f5653f : AbstractC0343o.f5651d;
        Activity currentActivity = getCurrentActivity();
        Dialog dialog = new Dialog(currentActivity != null ? currentActivity : getContext(), i3);
        this.f7844b = dialog;
        Window window3 = dialog.getWindow();
        Objects.requireNonNull(window3);
        window3.setFlags(8, 8);
        dialog.setContentView(getContentView());
        g();
        dialog.setOnShowListener(this.f7846d);
        dialog.setOnKeyListener(new d());
        Window window4 = dialog.getWindow();
        if (window4 != null) {
            window4.setSoftInputMode(16);
        }
        if (this.f7851i && (window2 = dialog.getWindow()) != null) {
            window2.addFlags(16777216);
        }
        if (b(currentActivity) && (window = dialog.getWindow()) != null) {
            window.setFlags(8192, 8192);
        }
        if (currentActivity == null || currentActivity.isFinishing()) {
            return;
        }
        dialog.show();
        h();
        Window window5 = dialog.getWindow();
        if (window5 != null) {
            window5.clearFlags(8);
        }
    }

    @Override // android.view.View
    public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        j.f(accessibilityEvent, "event");
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchProvideStructure(ViewStructure viewStructure) {
        j.f(viewStructure, "structure");
        this.f7852j.dispatchProvideStructure(viewStructure);
    }

    public final String getAnimationType() {
        return this.f7850h;
    }

    @Override // android.view.ViewGroup
    public View getChildAt(int i3) {
        return this.f7852j.getChildAt(i3);
    }

    @Override // android.view.ViewGroup
    public int getChildCount() {
        return this.f7852j.getChildCount();
    }

    public final Dialog getDialog() {
        return this.f7844b;
    }

    public final EventDispatcher getEventDispatcher() {
        return this.f7852j.getEventDispatcher$ReactAndroid_release();
    }

    public final boolean getHardwareAccelerated() {
        return this.f7851i;
    }

    public final boolean getNavigationBarTranslucent() {
        return this.f7849g;
    }

    public final InterfaceC0116c getOnRequestCloseListener() {
        return this.f7847e;
    }

    public final DialogInterface.OnShowListener getOnShowListener() {
        return this.f7846d;
    }

    public final A0 getStateWrapper() {
        return this.f7852j.getStateWrapper$ReactAndroid_release();
    }

    public final boolean getStatusBarTranslucent() {
        return this.f7848f;
    }

    public final boolean getTransparent() {
        return this.f7845c;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        Context context = getContext();
        j.d(context, "null cannot be cast to non-null type com.facebook.react.uimanager.ThemedReactContext");
        ((B0) context).addLifecycleEventListener(this);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        c();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        c();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
        d();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public void removeView(View view) {
        UiThreadUtil.assertOnUiThread();
        if (view != null) {
            this.f7852j.removeView(view);
        }
    }

    @Override // android.view.ViewGroup
    public void removeViewAt(int i3) {
        UiThreadUtil.assertOnUiThread();
        this.f7852j.removeView(getChildAt(i3));
    }

    public final void setAnimationType(String str) {
        this.f7850h = str;
        this.f7853k = true;
    }

    public final void setDialogRootViewGroupTestId(String str) {
        this.f7852j.setTag(AbstractC0339k.f5596t, str);
    }

    public final void setEventDispatcher(EventDispatcher eventDispatcher) {
        this.f7852j.setEventDispatcher$ReactAndroid_release(eventDispatcher);
    }

    public final void setHardwareAccelerated(boolean z3) {
        this.f7851i = z3;
        this.f7853k = true;
    }

    @Override // android.view.View
    public void setId(int i3) {
        super.setId(i3);
        this.f7852j.setId(i3);
    }

    public final void setNavigationBarTranslucent(boolean z3) {
        this.f7849g = z3;
        this.f7853k = true;
    }

    public final void setOnRequestCloseListener(InterfaceC0116c interfaceC0116c) {
        this.f7847e = interfaceC0116c;
    }

    public final void setOnShowListener(DialogInterface.OnShowListener onShowListener) {
        this.f7846d = onShowListener;
    }

    public final void setStateWrapper(A0 a02) {
        this.f7852j.setStateWrapper$ReactAndroid_release(a02);
    }

    public final void setStatusBarTranslucent(boolean z3) {
        this.f7848f = z3;
        this.f7853k = true;
    }

    public final void setTransparent(boolean z3) {
        this.f7845c = z3;
    }
}
