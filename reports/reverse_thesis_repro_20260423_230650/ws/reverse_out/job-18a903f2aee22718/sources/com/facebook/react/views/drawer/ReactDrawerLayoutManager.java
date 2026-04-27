package com.facebook.react.views.drawer;

import V1.c;
import V1.d;
import android.view.View;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.Q0;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.events.EventDispatcher;
import h2.n;
import i2.D;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import u1.InterfaceC0703a;
import x.AbstractC0715a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactDrawerLayoutManager.REACT_CLASS)
public final class ReactDrawerLayoutManager extends ViewGroupManager<com.facebook.react.views.drawer.a> implements T1.b {
    public static final int CLOSE_DRAWER = 2;
    public static final String COMMAND_CLOSE_DRAWER = "closeDrawer";
    public static final String COMMAND_OPEN_DRAWER = "openDrawer";
    public static final a Companion = new a(null);
    private static final String DRAWER_POSITION = "DrawerPosition";
    private static final String DRAWER_POSITION_LEFT = "Left";
    private static final String DRAWER_POSITION_RIGHT = "Right";
    public static final int OPEN_DRAWER = 1;
    public static final String REACT_CLASS = "AndroidDrawerLayout";
    private final Q0 delegate = new T1.a(this);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public static final class b implements AbstractC0715a.d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final AbstractC0715a f7784a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final EventDispatcher f7785b;

        public b(AbstractC0715a abstractC0715a, EventDispatcher eventDispatcher) {
            j.f(abstractC0715a, "drawerLayout");
            j.f(eventDispatcher, "eventDispatcher");
            this.f7784a = abstractC0715a;
            this.f7785b = eventDispatcher;
        }

        @Override // x.AbstractC0715a.d
        public void a(int i3) {
            this.f7785b.g(new d(H0.f(this.f7784a), this.f7784a.getId(), i3));
        }

        @Override // x.AbstractC0715a.d
        public void b(View view, float f3) {
            j.f(view, "view");
            this.f7785b.g(new c(H0.f(this.f7784a), this.f7784a.getId(), f3));
        }

        @Override // x.AbstractC0715a.d
        public void c(View view) {
            j.f(view, "view");
            this.f7785b.g(new V1.b(H0.f(this.f7784a), this.f7784a.getId()));
        }

        @Override // x.AbstractC0715a.d
        public void d(View view) {
            j.f(view, "view");
            this.f7785b.g(new V1.a(H0.f(this.f7784a), this.f7784a.getId()));
        }
    }

    private final void setDrawerPositionInternal(com.facebook.react.views.drawer.a aVar, String str) {
        if (j.b(str, "left")) {
            aVar.setDrawerPosition$ReactAndroid_release(8388611);
            return;
        }
        if (j.b(str, "right")) {
            aVar.setDrawerPosition$ReactAndroid_release(8388613);
            return;
        }
        Y.a.I("ReactNative", "drawerPosition must be 'left' or 'right', received" + str);
        aVar.setDrawerPosition$ReactAndroid_release(8388611);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Integer> getCommandsMap() {
        return D.h(n.a(COMMAND_OPEN_DRAWER, 1), n.a(COMMAND_CLOSE_DRAWER, 2));
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Q0 getDelegate() {
        return this.delegate;
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new LinkedHashMap<>();
        }
        exportedCustomDirectEventTypeConstants.put("topDrawerSlide", D.d(n.a("registrationName", "onDrawerSlide")));
        exportedCustomDirectEventTypeConstants.put("topDrawerOpen", D.d(n.a("registrationName", "onDrawerOpen")));
        exportedCustomDirectEventTypeConstants.put("topDrawerClose", D.d(n.a("registrationName", "onDrawerClose")));
        exportedCustomDirectEventTypeConstants.put("topDrawerStateChanged", D.d(n.a("registrationName", "onDrawerStateChanged")));
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedViewConstants() {
        return D.d(n.a(DRAWER_POSITION, D.h(n.a(DRAWER_POSITION_LEFT, 8388611), n.a(DRAWER_POSITION_RIGHT, 8388613))));
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.O
    public boolean needsCustomLayoutForChildren() {
        return true;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.N
    public /* bridge */ /* synthetic */ void removeAllViews(View view) {
        super.removeAllViews(view);
    }

    @Override // T1.b
    @K1.a(customType = "Color", name = "drawerBackgroundColor")
    public void setDrawerBackgroundColor(com.facebook.react.views.drawer.a aVar, Integer num) {
        j.f(aVar, "view");
    }

    @Override // T1.b
    @K1.a(name = "keyboardDismissMode")
    public void setKeyboardDismissMode(com.facebook.react.views.drawer.a aVar, String str) {
        j.f(aVar, "view");
    }

    @Override // T1.b
    @K1.a(customType = "Color", name = "statusBarBackgroundColor")
    public void setStatusBarBackgroundColor(com.facebook.react.views.drawer.a aVar, Integer num) {
        j.f(aVar, "view");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public void addEventEmitters(B0 b02, com.facebook.react.views.drawer.a aVar) {
        j.f(b02, "reactContext");
        j.f(aVar, "view");
        EventDispatcher eventDispatcherC = H0.c(b02, aVar.getId());
        if (eventDispatcherC == null) {
            return;
        }
        aVar.a(new b(aVar, eventDispatcherC));
    }

    @Override // T1.b
    public void closeDrawer(com.facebook.react.views.drawer.a aVar) {
        j.f(aVar, "view");
        aVar.V();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public com.facebook.react.views.drawer.a createViewInstance(B0 b02) {
        j.f(b02, "context");
        return new com.facebook.react.views.drawer.a(b02);
    }

    @Override // T1.b
    public void openDrawer(com.facebook.react.views.drawer.a aVar) {
        j.f(aVar, "view");
        aVar.W();
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0030, code lost:
    
        if (r5.equals("unlocked") != false) goto L22;
     */
    @Override // T1.b
    @K1.a(name = "drawerLockMode")
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setDrawerLockMode(com.facebook.react.views.drawer.a r4, java.lang.String r5) {
        /*
            r3 = this;
            java.lang.String r0 = "view"
            t2.j.f(r4, r0)
            r0 = 0
            if (r5 == 0) goto L5a
            int r1 = r5.hashCode()
            r2 = -1292600945(0xffffffffb2f4798f, float:-2.8460617E-8)
            if (r1 == r2) goto L33
            r2 = -210949405(0xfffffffff36d2ae3, float:-1.8790347E31)
            if (r1 == r2) goto L2a
            r2 = 168848173(0xa106b2d, float:6.953505E-33)
            if (r1 == r2) goto L1c
            goto L3b
        L1c:
            java.lang.String r1 = "locked-open"
            boolean r1 = r5.equals(r1)
            if (r1 != 0) goto L25
            goto L3b
        L25:
            r5 = 2
            r4.setDrawerLockMode(r5)
            goto L5d
        L2a:
            java.lang.String r1 = "unlocked"
            boolean r1 = r5.equals(r1)
            if (r1 == 0) goto L3b
            goto L5a
        L33:
            java.lang.String r1 = "locked-closed"
            boolean r1 = r5.equals(r1)
            if (r1 != 0) goto L55
        L3b:
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Unknown drawerLockMode "
            r1.append(r2)
            r1.append(r5)
            java.lang.String r5 = r1.toString()
            java.lang.String r1 = "ReactNative"
            Y.a.I(r1, r5)
            r4.setDrawerLockMode(r0)
            goto L5d
        L55:
            r5 = 1
            r4.setDrawerLockMode(r5)
            goto L5d
        L5a:
            r4.setDrawerLockMode(r0)
        L5d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.drawer.ReactDrawerLayoutManager.setDrawerLockMode(com.facebook.react.views.drawer.a, java.lang.String):void");
    }

    @Override // T1.b
    public void setDrawerPosition(com.facebook.react.views.drawer.a aVar, String str) {
        j.f(aVar, "view");
        if (str == null) {
            aVar.setDrawerPosition$ReactAndroid_release(8388611);
        } else {
            setDrawerPositionInternal(aVar, str);
        }
    }

    @K1.a(defaultFloat = Float.NaN, name = "drawerWidth")
    public final void setDrawerWidth(com.facebook.react.views.drawer.a aVar, float f3) {
        j.f(aVar, "view");
        aVar.setDrawerWidth$ReactAndroid_release(Float.isNaN(f3) ? -1 : Math.round(C0444f0.f7603a.b(f3)));
    }

    @Override // com.facebook.react.uimanager.BaseViewManager
    public void setElevation(com.facebook.react.views.drawer.a aVar, float f3) {
        j.f(aVar, "view");
        aVar.setDrawerElevation(C0444f0.f7603a.b(f3));
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager
    public void addView(com.facebook.react.views.drawer.a aVar, View view, int i3) {
        j.f(aVar, "parent");
        j.f(view, "child");
        if (getChildCount(aVar) >= 2) {
            throw new JSApplicationIllegalArgumentException("The Drawer cannot have more than two children");
        }
        if (i3 != 0 && i3 != 1) {
            throw new JSApplicationIllegalArgumentException("The only valid indices for drawer's child are 0 or 1. Got " + i3 + " instead.");
        }
        aVar.addView(view, i3);
        aVar.X();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(com.facebook.react.views.drawer.a aVar, int i3, ReadableArray readableArray) {
        j.f(aVar, "root");
        if (i3 == 1) {
            aVar.W();
        } else {
            if (i3 != 2) {
                return;
            }
            aVar.V();
        }
    }

    @K1.a(name = "drawerPosition")
    public final void setDrawerPosition(com.facebook.react.views.drawer.a aVar, Dynamic dynamic) {
        j.f(aVar, "view");
        j.f(dynamic, "drawerPosition");
        if (dynamic.isNull()) {
            aVar.setDrawerPosition$ReactAndroid_release(8388611);
            return;
        }
        if (dynamic.getType() == ReadableType.Number) {
            int iAsInt = dynamic.asInt();
            if (8388611 != iAsInt && 8388613 != iAsInt) {
                Y.a.I("ReactNative", "Unknown drawerPosition " + iAsInt);
                aVar.setDrawerPosition$ReactAndroid_release(8388611);
                return;
            }
            aVar.setDrawerPosition$ReactAndroid_release(iAsInt);
            return;
        }
        if (dynamic.getType() == ReadableType.String) {
            setDrawerPositionInternal(aVar, dynamic.asString());
        } else {
            Y.a.I("ReactNative", "drawerPosition must be a string or int");
            aVar.setDrawerPosition$ReactAndroid_release(8388611);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(com.facebook.react.views.drawer.a aVar, String str, ReadableArray readableArray) {
        j.f(aVar, "root");
        j.f(str, "commandId");
        if (j.b(str, COMMAND_OPEN_DRAWER)) {
            aVar.W();
        } else if (j.b(str, COMMAND_CLOSE_DRAWER)) {
            aVar.V();
        }
    }

    @Override // T1.b
    public void setDrawerWidth(com.facebook.react.views.drawer.a aVar, Float f3) {
        int iRound;
        j.f(aVar, "view");
        if (f3 != null) {
            iRound = Math.round(C0444f0.f7603a.b(f3.floatValue()));
        } else {
            iRound = -1;
        }
        aVar.setDrawerWidth$ReactAndroid_release(iRound);
    }
}
