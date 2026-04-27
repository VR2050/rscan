package com.facebook.react.views.unimplementedview;

import T1.q;
import T1.r;
import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.Q0;
import com.facebook.react.uimanager.ViewGroupManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactUnimplementedViewManager.REACT_CLASS)
public final class ReactUnimplementedViewManager extends ViewGroupManager<com.facebook.react.views.unimplementedview.a> implements r {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "UnimplementedNativeView";
    private final Q0 delegate = new q(this);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Q0 getDelegate() {
        return this.delegate;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.N
    public /* bridge */ /* synthetic */ void removeAllViews(View view) {
        super.removeAllViews(view);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public com.facebook.react.views.unimplementedview.a createViewInstance(B0 b02) {
        j.f(b02, "reactContext");
        return new com.facebook.react.views.unimplementedview.a(b02);
    }

    @Override // T1.r
    @K1.a(name = "name")
    public void setName(com.facebook.react.views.unimplementedview.a aVar, String str) {
        j.f(aVar, "view");
        if (str == null) {
            str = "<null component name>";
        }
        aVar.setName$ReactAndroid_release(str);
    }
}
