package com.facebook.react.views.switchview;

import T1.g;
import T1.h;
import android.content.Context;
import android.view.View;
import android.widget.CompoundButton;
import com.facebook.react.animated.NativeAnimatedModule;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.BaseViewManager;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.Q0;
import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.yoga.p;
import com.facebook.yoga.q;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class ReactSwitchManager extends BaseViewManager<com.facebook.react.views.switchview.a, d> implements h {
    public static final a Companion = new a(null);
    private static final CompoundButton.OnCheckedChangeListener ON_CHECKED_CHANGE_LISTENER = new CompoundButton.OnCheckedChangeListener() { // from class: com.facebook.react.views.switchview.c
        @Override // android.widget.CompoundButton.OnCheckedChangeListener
        public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) {
            ReactSwitchManager.ON_CHECKED_CHANGE_LISTENER$lambda$2(compoundButton, z3);
        }
    };
    public static final String REACT_CLASS = "AndroidSwitch";
    private final Q0 delegate = new g(this);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void ON_CHECKED_CHANGE_LISTENER$lambda$2(CompoundButton compoundButton, boolean z3) {
        Context context = compoundButton.getContext();
        j.d(context, "null cannot be cast to non-null type com.facebook.react.bridge.ReactContext");
        ReactContext reactContext = (ReactContext) context;
        int id = compoundButton.getId();
        EventDispatcher eventDispatcherC = H0.c(reactContext, id);
        if (eventDispatcherC != null) {
            eventDispatcherC.g(new b(H0.e(reactContext), id, z3));
        }
    }

    private final void setValueInternal(com.facebook.react.views.switchview.a aVar, boolean z3) {
        aVar.setOnCheckedChangeListener(null);
        aVar.setOn(z3);
        aVar.setOnCheckedChangeListener(ON_CHECKED_CHANGE_LISTENER);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected Q0 getDelegate() {
        return this.delegate;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<d> getShadowNodeClass() {
        return d.class;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public long measure(Context context, ReadableMap readableMap, ReadableMap readableMap2, ReadableMap readableMap3, float f3, p pVar, float f4, p pVar2, float[] fArr) {
        j.f(context, "context");
        j.f(pVar, "widthMode");
        j.f(pVar2, "heightMode");
        com.facebook.react.views.switchview.a aVar = new com.facebook.react.views.switchview.a(context);
        aVar.setShowText(false);
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(0, 0);
        aVar.measure(iMakeMeasureSpec, iMakeMeasureSpec);
        return q.a(C0444f0.f(aVar.getMeasuredWidth()), C0444f0.f(aVar.getMeasuredHeight()));
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(com.facebook.react.views.switchview.a aVar, Object obj) {
        j.f(aVar, "root");
        j.f(obj, "extraData");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public void addEventEmitters(B0 b02, com.facebook.react.views.switchview.a aVar) {
        j.f(b02, "reactContext");
        j.f(aVar, "view");
        aVar.setOnCheckedChangeListener(ON_CHECKED_CHANGE_LISTENER);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public d createShadowNodeInstance() {
        return new d();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public com.facebook.react.views.switchview.a createViewInstance(B0 b02) {
        j.f(b02, "context");
        com.facebook.react.views.switchview.a aVar = new com.facebook.react.views.switchview.a(b02);
        aVar.setShowText(false);
        return aVar;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void receiveCommand(com.facebook.react.views.switchview.a aVar, String str, ReadableArray readableArray) {
        j.f(aVar, "view");
        j.f(str, "commandId");
        if (j.b(str, "setNativeValue")) {
            setValueInternal(aVar, readableArray != null ? readableArray.getBoolean(0) : false);
        }
    }

    @Override // com.facebook.react.uimanager.BaseViewManager
    public void setBackgroundColor(com.facebook.react.views.switchview.a aVar, int i3) {
        j.f(aVar, "view");
        aVar.setBackgroundColor(i3);
    }

    @Override // T1.h
    @K1.a(defaultBoolean = NativeAnimatedModule.ANIMATED_MODULE_DEBUG, name = "disabled")
    public void setDisabled(com.facebook.react.views.switchview.a aVar, boolean z3) {
        j.f(aVar, "view");
        aVar.setEnabled(!z3);
    }

    @Override // T1.h
    @K1.a(defaultBoolean = true, name = "enabled")
    public void setEnabled(com.facebook.react.views.switchview.a aVar, boolean z3) {
        j.f(aVar, "view");
        aVar.setEnabled(z3);
    }

    @Override // T1.h
    public void setNativeValue(com.facebook.react.views.switchview.a aVar, boolean z3) {
        j.f(aVar, "view");
        setValueInternal(aVar, z3);
    }

    @Override // T1.h
    @K1.a(name = "on")
    public void setOn(com.facebook.react.views.switchview.a aVar, boolean z3) {
        j.f(aVar, "view");
        setValueInternal(aVar, z3);
    }

    @Override // T1.h
    @K1.a(customType = "Color", name = "thumbColor")
    public void setThumbColor(com.facebook.react.views.switchview.a aVar, Integer num) {
        j.f(aVar, "view");
        aVar.setThumbColor(num);
    }

    @Override // T1.h
    @K1.a(customType = "Color", name = "thumbTintColor")
    public void setThumbTintColor(com.facebook.react.views.switchview.a aVar, Integer num) {
        j.f(aVar, "view");
        setThumbColor(aVar, num);
    }

    @Override // T1.h
    @K1.a(customType = "Color", name = "trackColorForFalse")
    public void setTrackColorForFalse(com.facebook.react.views.switchview.a aVar, Integer num) {
        j.f(aVar, "view");
        aVar.setTrackColorForFalse(num);
    }

    @Override // T1.h
    @K1.a(customType = "Color", name = "trackColorForTrue")
    public void setTrackColorForTrue(com.facebook.react.views.switchview.a aVar, Integer num) {
        j.f(aVar, "view");
        aVar.setTrackColorForTrue(num);
    }

    @Override // T1.h
    @K1.a(customType = "Color", name = "trackTintColor")
    public void setTrackTintColor(com.facebook.react.views.switchview.a aVar, Integer num) {
        j.f(aVar, "view");
        aVar.setTrackColor(num);
    }

    @Override // T1.h
    @K1.a(name = "value")
    public void setValue(com.facebook.react.views.switchview.a aVar, boolean z3) {
        j.f(aVar, "view");
        setValueInternal(aVar, z3);
    }
}
