package com.facebook.react.views.image;

import android.graphics.PorterDuff;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0433a;
import com.facebook.react.uimanager.SimpleViewManager;
import com.facebook.react.uimanager.W;
import com.facebook.react.uimanager.X;
import com.facebook.react.views.image.b;
import h2.n;
import i2.D;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import l0.AbstractC0616d;
import p0.AbstractC0643b;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = ReactImageManager.REACT_CLASS)
public final class ReactImageManager extends SimpleViewManager<h> {
    public static final a Companion = new a(null);
    private static final String ON_ERROR = "onError";
    private static final String ON_LOAD = "onLoad";
    private static final String ON_LOAD_END = "onLoadEnd";
    private static final String ON_LOAD_START = "onLoadStart";
    private static final String ON_PROGRESS = "onProgress";
    public static final String REACT_CLASS = "RCTImageView";
    private static final String REGISTRATION_NAME = "registrationName";
    private Object callerContext;
    private final f callerContextFactory;
    private final AbstractC0643b draweeControllerBuilder;
    private final com.facebook.react.views.image.a globalImageLoadListener;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public ReactImageManager() {
        this(null, null, null, 7, null);
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Object> getExportedCustomDirectEventTypeConstants() {
        Map<String, Object> exportedCustomDirectEventTypeConstants = super.getExportedCustomDirectEventTypeConstants();
        if (exportedCustomDirectEventTypeConstants == null) {
            exportedCustomDirectEventTypeConstants = new LinkedHashMap<>();
        }
        b.a aVar = b.f7790o;
        exportedCustomDirectEventTypeConstants.put(aVar.f(4), D.d(n.a(REGISTRATION_NAME, ON_LOAD_START)));
        exportedCustomDirectEventTypeConstants.put(aVar.f(5), D.d(n.a(REGISTRATION_NAME, ON_PROGRESS)));
        exportedCustomDirectEventTypeConstants.put(aVar.f(2), D.d(n.a(REGISTRATION_NAME, ON_LOAD)));
        exportedCustomDirectEventTypeConstants.put(aVar.f(1), D.d(n.a(REGISTRATION_NAME, ON_ERROR)));
        exportedCustomDirectEventTypeConstants.put(aVar.f(3), D.d(n.a(REGISTRATION_NAME, ON_LOAD_END)));
        return exportedCustomDirectEventTypeConstants;
    }

    @Override // com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @K1.a(name = "accessible")
    public final void setAccessible(h hVar, boolean z3) {
        j.f(hVar, "view");
        hVar.setFocusable(z3);
    }

    @K1.a(name = "blurRadius")
    public final void setBlurRadius(h hVar, float f3) {
        j.f(hVar, "view");
        hVar.setBlurRadius(f3);
    }

    @K1.a(customType = "Color", name = "borderColor")
    public final void setBorderColor(h hVar, Integer num) {
        j.f(hVar, "view");
        C0433a.p(hVar, Q1.n.f2478c, num);
    }

    @K1.b(defaultFloat = Float.NaN, names = {"borderRadius", "borderTopLeftRadius", "borderTopRightRadius", "borderBottomRightRadius", "borderBottomLeftRadius"})
    public final void setBorderRadius(h hVar, int i3, float f3) {
        j.f(hVar, "view");
        C0433a.q(hVar, Q1.d.values()[i3], Float.isNaN(f3) ? null : new W(f3, X.f7535b));
    }

    @K1.a(name = "borderWidth")
    public final void setBorderWidth(h hVar, float f3) {
        j.f(hVar, "view");
        C0433a.s(hVar, Q1.n.f2478c, Float.valueOf(f3));
    }

    @K1.a(name = "defaultSource")
    public final void setDefaultSource(h hVar, String str) {
        j.f(hVar, "view");
        hVar.setDefaultSource(str);
    }

    @K1.a(name = "fadeDuration")
    public final void setFadeDuration(h hVar, int i3) {
        j.f(hVar, "view");
        hVar.setFadeDuration(i3);
    }

    @K1.a(name = "headers")
    public final void setHeaders(h hVar, ReadableMap readableMap) {
        j.f(hVar, "view");
        if (readableMap != null) {
            hVar.setHeaders(readableMap);
        }
    }

    @K1.a(name = "internal_analyticTag")
    public final void setInternal_AnalyticsTag(h hVar, String str) {
        j.f(hVar, "view");
    }

    @K1.a(name = "shouldNotifyLoadEvents")
    public final void setLoadHandlersRegistered(h hVar, boolean z3) {
        j.f(hVar, "view");
        hVar.setShouldNotifyLoadEvents(z3);
    }

    @K1.a(name = "loadingIndicatorSrc")
    public final void setLoadingIndicatorSource(h hVar, String str) {
        j.f(hVar, "view");
        hVar.setLoadingIndicatorSource(str);
    }

    @K1.a(customType = "Color", name = "overlayColor")
    public final void setOverlayColor(h hVar, Integer num) {
        j.f(hVar, "view");
        if (num == null) {
            hVar.setOverlayColor(0);
        } else {
            hVar.setOverlayColor(num.intValue());
        }
    }

    @K1.a(name = "progressiveRenderingEnabled")
    public final void setProgressiveRenderingEnabled(h hVar, boolean z3) {
        j.f(hVar, "view");
        hVar.setProgressiveRenderingEnabled(z3);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x0033, code lost:
    
        if (r3.equals("auto") == false) goto L20;
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @K1.a(name = "resizeMethod")
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void setResizeMethod(com.facebook.react.views.image.h r2, java.lang.String r3) {
        /*
            r1 = this;
            java.lang.String r0 = "view"
            t2.j.f(r2, r0)
            if (r3 == 0) goto L65
            int r0 = r3.hashCode()
            switch(r0) {
                case -934437708: goto L36;
                case 3005871: goto L2d;
                case 3387192: goto L1e;
                case 109250890: goto Lf;
                default: goto Le;
            }
        Le:
            goto L3e
        Lf:
            java.lang.String r0 = "scale"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L18
            goto L3e
        L18:
            com.facebook.react.views.image.c r3 = com.facebook.react.views.image.c.f7800d
            r2.setResizeMethod(r3)
            goto L6a
        L1e:
            java.lang.String r0 = "none"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L27
            goto L3e
        L27:
            com.facebook.react.views.image.c r3 = com.facebook.react.views.image.c.f7801e
            r2.setResizeMethod(r3)
            goto L6a
        L2d:
            java.lang.String r0 = "auto"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L65
            goto L3e
        L36:
            java.lang.String r0 = "resize"
            boolean r0 = r3.equals(r0)
            if (r0 != 0) goto L5f
        L3e:
            com.facebook.react.views.image.c r0 = com.facebook.react.views.image.c.f7798b
            r2.setResizeMethod(r0)
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.String r0 = "Invalid resize method: '"
            r2.append(r0)
            r2.append(r3)
            java.lang.String r3 = "'"
            r2.append(r3)
            java.lang.String r2 = r2.toString()
            java.lang.String r3 = "ReactNative"
            Y.a.I(r3, r2)
            goto L6a
        L5f:
            com.facebook.react.views.image.c r3 = com.facebook.react.views.image.c.f7799c
            r2.setResizeMethod(r3)
            goto L6a
        L65:
            com.facebook.react.views.image.c r3 = com.facebook.react.views.image.c.f7798b
            r2.setResizeMethod(r3)
        L6a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.views.image.ReactImageManager.setResizeMethod(com.facebook.react.views.image.h, java.lang.String):void");
    }

    @K1.a(name = "resizeMode")
    public final void setResizeMode(h hVar, String str) {
        j.f(hVar, "view");
        hVar.setScaleType(d.c(str));
        hVar.setTileMode(d.d(str));
    }

    @K1.a(name = "resizeMultiplier")
    public final void setResizeMultiplier(h hVar, float f3) {
        j.f(hVar, "view");
        if (f3 < 0.01f) {
            Y.a.I("ReactNative", "Invalid resize multiplier: '" + f3 + "'");
        }
        hVar.setResizeMultiplier(f3);
    }

    @K1.a(name = "source")
    public final void setSource(h hVar, ReadableArray readableArray) {
        j.f(hVar, "view");
        hVar.setSource(readableArray);
    }

    @K1.a(name = "src")
    public final void setSrc(h hVar, ReadableArray readableArray) {
        j.f(hVar, "view");
        setSource(hVar, readableArray);
    }

    @K1.a(customType = "Color", name = "tintColor")
    public final void setTintColor(h hVar, Integer num) {
        j.f(hVar, "view");
        if (num == null) {
            hVar.clearColorFilter();
        } else {
            hVar.setColorFilter(num.intValue(), PorterDuff.Mode.SRC_IN);
        }
    }

    public ReactImageManager(AbstractC0643b abstractC0643b) {
        this(abstractC0643b, null, null, 6, null);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public h createViewInstance(B0 b02) {
        j.f(b02, "context");
        Object obj = this.callerContext;
        if (obj == null) {
            obj = null;
        }
        AbstractC0643b abstractC0643bF = this.draweeControllerBuilder;
        if (abstractC0643bF == null) {
            abstractC0643bF = AbstractC0616d.f();
        }
        j.c(abstractC0643bF);
        return new h(b02, abstractC0643bF, null, obj);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public void onAfterUpdateTransaction(h hVar) {
        j.f(hVar, "view");
        super.onAfterUpdateTransaction(hVar);
        hVar.n();
    }

    public ReactImageManager(AbstractC0643b abstractC0643b, com.facebook.react.views.image.a aVar) {
        this(abstractC0643b, aVar, null, 4, null);
    }

    public /* synthetic */ ReactImageManager(AbstractC0643b abstractC0643b, com.facebook.react.views.image.a aVar, f fVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? null : abstractC0643b, (i3 & 2) != 0 ? null : aVar, (i3 & 4) != 0 ? null : fVar);
    }

    public ReactImageManager(AbstractC0643b abstractC0643b, com.facebook.react.views.image.a aVar, f fVar) {
        this.draweeControllerBuilder = abstractC0643b;
    }

    public ReactImageManager(AbstractC0643b abstractC0643b, Object obj) {
        this(abstractC0643b, (com.facebook.react.views.image.a) null, (f) null);
        this.callerContext = obj;
    }

    public ReactImageManager(AbstractC0643b abstractC0643b, com.facebook.react.views.image.a aVar, Object obj) {
        this(abstractC0643b, aVar, (f) null);
        this.callerContext = obj;
    }
}
