package com.facebook.react.views.text.frescosupport;

import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.BaseViewManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import l0.AbstractC0616d;
import p0.AbstractC0643b;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = FrescoBasedReactTextInlineImageViewManager.REACT_CLASS)
public final class FrescoBasedReactTextInlineImageViewManager extends BaseViewManager<View, com.facebook.react.views.text.frescosupport.a> {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RCTTextInlineImage";
    private final Object callerContext;
    private final AbstractC0643b draweeControllerBuilder;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public FrescoBasedReactTextInlineImageViewManager() {
        this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    protected View createViewInstance(B0 b02) {
        j.f(b02, "context");
        throw new IllegalStateException("RCTTextInlineImage doesn't map into a native view");
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Class<com.facebook.react.views.text.frescosupport.a> getShadowNodeClass() {
        return com.facebook.react.views.text.frescosupport.a.class;
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public void updateExtraData(View view, Object obj) {
        j.f(view, "root");
        j.f(obj, "extraData");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public FrescoBasedReactTextInlineImageViewManager(AbstractC0643b abstractC0643b) {
        DefaultConstructorMarker defaultConstructorMarker = null;
        this(abstractC0643b, defaultConstructorMarker, 2, defaultConstructorMarker);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public com.facebook.react.views.text.frescosupport.a createShadowNodeInstance() {
        AbstractC0643b abstractC0643bF = this.draweeControllerBuilder;
        if (abstractC0643bF == null) {
            abstractC0643bF = AbstractC0616d.f();
        }
        return new com.facebook.react.views.text.frescosupport.a(abstractC0643bF, this.callerContext);
    }

    public /* synthetic */ FrescoBasedReactTextInlineImageViewManager(AbstractC0643b abstractC0643b, Object obj, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? null : abstractC0643b, (i3 & 2) != 0 ? null : obj);
    }

    public FrescoBasedReactTextInlineImageViewManager(AbstractC0643b abstractC0643b, Object obj) {
        this.draweeControllerBuilder = abstractC0643b;
        this.callerContext = obj;
    }
}
