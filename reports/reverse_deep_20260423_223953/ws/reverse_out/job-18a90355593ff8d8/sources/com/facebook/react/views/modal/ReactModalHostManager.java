package com.facebook.react.views.modal;

import T1.k;
import T1.l;
import android.content.DialogInterface;
import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.Q0;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.views.modal.c;
import h2.n;
import i2.D;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactModalHostManager.REACT_CLASS)
public final class ReactModalHostManager extends ViewGroupManager<c> implements l {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RCTModalHostView";
    private final Q0 delegate = new k(this);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void addEventEmitters$lambda$0(EventDispatcher eventDispatcher, B0 b02, c cVar, DialogInterface dialogInterface) {
        eventDispatcher.g(new d(H0.e(b02), cVar.getId()));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void addEventEmitters$lambda$1(EventDispatcher eventDispatcher, B0 b02, c cVar, DialogInterface dialogInterface) {
        eventDispatcher.g(new e(H0.e(b02), cVar.getId()));
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
        exportedCustomDirectEventTypeConstants.put("topRequestClose", D.d(n.a("registrationName", "onRequestClose")));
        exportedCustomDirectEventTypeConstants.put("topShow", D.d(n.a("registrationName", "onShow")));
        exportedCustomDirectEventTypeConstants.put("topDismiss", D.d(n.a("registrationName", "onDismiss")));
        exportedCustomDirectEventTypeConstants.put("topOrientationChange", D.d(n.a("registrationName", "onOrientationChange")));
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.N
    public /* bridge */ /* synthetic */ void removeAllViews(View view) {
        super.removeAllViews(view);
    }

    @Override // T1.l
    @K1.a(name = "animated")
    public void setAnimated(c cVar, boolean z3) {
        j.f(cVar, "view");
    }

    @Override // T1.l
    @K1.a(name = "identifier")
    public void setIdentifier(c cVar, int i3) {
        j.f(cVar, "view");
    }

    @Override // T1.l
    @K1.a(name = "presentationStyle")
    public void setPresentationStyle(c cVar, String str) {
        j.f(cVar, "view");
    }

    @Override // T1.l
    @K1.a(name = "supportedOrientations")
    public void setSupportedOrientations(c cVar, ReadableArray readableArray) {
        j.f(cVar, "view");
    }

    @Override // T1.l
    @K1.a(name = "visible")
    public void setVisible(c cVar, boolean z3) {
        j.f(cVar, "view");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public void addEventEmitters(final B0 b02, final c cVar) {
        j.f(b02, "reactContext");
        j.f(cVar, "view");
        final EventDispatcher eventDispatcherC = H0.c(b02, cVar.getId());
        if (eventDispatcherC != null) {
            cVar.setOnRequestCloseListener(new c.InterfaceC0116c() { // from class: com.facebook.react.views.modal.a
                @Override // com.facebook.react.views.modal.c.InterfaceC0116c
                public final void a(DialogInterface dialogInterface) {
                    ReactModalHostManager.addEventEmitters$lambda$0(eventDispatcherC, b02, cVar, dialogInterface);
                }
            });
            cVar.setOnShowListener(new DialogInterface.OnShowListener() { // from class: com.facebook.react.views.modal.b
                @Override // android.content.DialogInterface.OnShowListener
                public final void onShow(DialogInterface dialogInterface) {
                    ReactModalHostManager.addEventEmitters$lambda$1(eventDispatcherC, b02, cVar, dialogInterface);
                }
            });
            cVar.setEventDispatcher(eventDispatcherC);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public c createViewInstance(B0 b02) {
        j.f(b02, "reactContext");
        return new c(b02);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public void onAfterUpdateTransaction(c cVar) {
        j.f(cVar, "view");
        super.onAfterUpdateTransaction(cVar);
        cVar.d();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void onDropViewInstance(c cVar) {
        j.f(cVar, "view");
        super.onDropViewInstance(cVar);
        cVar.c();
    }

    @Override // T1.l
    @K1.a(name = "animationType")
    public void setAnimationType(c cVar, String str) {
        j.f(cVar, "view");
        if (str != null) {
            cVar.setAnimationType(str);
        }
    }

    @Override // T1.l
    @K1.a(name = "hardwareAccelerated")
    public void setHardwareAccelerated(c cVar, boolean z3) {
        j.f(cVar, "view");
        cVar.setHardwareAccelerated(z3);
    }

    @Override // T1.l
    @K1.a(name = "navigationBarTranslucent")
    public void setNavigationBarTranslucent(c cVar, boolean z3) {
        j.f(cVar, "view");
        cVar.setNavigationBarTranslucent(z3);
    }

    @Override // T1.l
    @K1.a(name = "statusBarTranslucent")
    public void setStatusBarTranslucent(c cVar, boolean z3) {
        j.f(cVar, "view");
        cVar.setStatusBarTranslucent(z3);
    }

    @Override // com.facebook.react.uimanager.BaseViewManager
    public void setTestId(c cVar, String str) {
        j.f(cVar, "view");
        super.setTestId(cVar, str);
        cVar.setDialogRootViewGroupTestId(str);
    }

    @Override // T1.l
    @K1.a(name = "transparent")
    public void setTransparent(c cVar, boolean z3) {
        j.f(cVar, "view");
        cVar.setTransparent(z3);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Object updateState(c cVar, C0469s0 c0469s0, A0 a02) {
        j.f(cVar, "view");
        j.f(c0469s0, "props");
        j.f(a02, "stateWrapper");
        cVar.setStateWrapper(a02);
        return null;
    }
}
