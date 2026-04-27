package com.facebook.react.views.text;

import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.ViewManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactRawTextManager.REACT_CLASS)
public final class ReactRawTextManager extends ViewManager<View, d> {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RCTRawText";

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
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
    protected View prepareToRecycleView(B0 b02, View view) {
        t2.j.f(b02, "reactContext");
        t2.j.f(view, "view");
        throw new IllegalStateException("Attempt to recycle a native view for RCTRawText");
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(View view, Object obj) {
        t2.j.f(view, "view");
        t2.j.f(obj, "extraData");
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public d createShadowNodeInstance() {
        return new d();
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public l createViewInstance(B0 b02) {
        t2.j.f(b02, "context");
        throw new IllegalStateException("Attempt to create a native view for RCTRawText");
    }
}
