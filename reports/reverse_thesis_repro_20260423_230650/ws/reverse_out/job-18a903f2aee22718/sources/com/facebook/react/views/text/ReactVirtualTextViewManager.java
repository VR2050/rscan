package com.facebook.react.views.text;

import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.BaseViewManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactVirtualTextViewManager.REACT_CLASS)
public final class ReactVirtualTextViewManager extends BaseViewManager<View, p> {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RCTVirtualText";

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected View createViewInstance(B0 b02) {
        t2.j.f(b02, "context");
        throw new IllegalStateException("Attempt to create a native view for RCTVirtualText");
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<p> getShadowNodeClass() {
        return p.class;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(View view, Object obj) {
        t2.j.f(view, "view");
        t2.j.f(obj, "extraData");
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public p createShadowNodeInstance() {
        return new p();
    }
}
