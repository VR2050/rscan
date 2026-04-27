package com.th3rdwave.safeareacontext;

import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.views.view.ReactViewManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = SafeAreaViewManager.REACT_CLASS)
public final class SafeAreaViewManager extends ReactViewManager {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RNCSafeAreaView";

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    @Override // com.facebook.react.views.view.ReactViewManager, com.facebook.react.uimanager.ViewManager, com.facebook.react.bridge.NativeModule
    public String getName() {
        return REACT_CLASS;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.ViewManager
    public Class<p> getShadowNodeClass() {
        return p.class;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0020  */
    @K1.a(name = "edges")
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void setEdges(com.th3rdwave.safeareacontext.k r6, com.facebook.react.bridge.ReadableMap r7) {
        /*
            r5 = this;
            java.lang.String r0 = "view"
            t2.j.f(r6, r0)
            if (r7 == 0) goto L75
            java.lang.String r0 = "top"
            java.lang.String r0 = r7.getString(r0)
            java.lang.String r1 = "toUpperCase(...)"
            if (r0 == 0) goto L20
            java.util.Locale r2 = java.util.Locale.ROOT
            java.lang.String r0 = r0.toUpperCase(r2)
            t2.j.e(r0, r1)
            com.th3rdwave.safeareacontext.l r0 = com.th3rdwave.safeareacontext.l.valueOf(r0)
            if (r0 != 0) goto L22
        L20:
            com.th3rdwave.safeareacontext.l r0 = com.th3rdwave.safeareacontext.l.f8757b
        L22:
            java.lang.String r2 = "right"
            java.lang.String r2 = r7.getString(r2)
            if (r2 == 0) goto L39
            java.util.Locale r3 = java.util.Locale.ROOT
            java.lang.String r2 = r2.toUpperCase(r3)
            t2.j.e(r2, r1)
            com.th3rdwave.safeareacontext.l r2 = com.th3rdwave.safeareacontext.l.valueOf(r2)
            if (r2 != 0) goto L3b
        L39:
            com.th3rdwave.safeareacontext.l r2 = com.th3rdwave.safeareacontext.l.f8757b
        L3b:
            java.lang.String r3 = "bottom"
            java.lang.String r3 = r7.getString(r3)
            if (r3 == 0) goto L52
            java.util.Locale r4 = java.util.Locale.ROOT
            java.lang.String r3 = r3.toUpperCase(r4)
            t2.j.e(r3, r1)
            com.th3rdwave.safeareacontext.l r3 = com.th3rdwave.safeareacontext.l.valueOf(r3)
            if (r3 != 0) goto L54
        L52:
            com.th3rdwave.safeareacontext.l r3 = com.th3rdwave.safeareacontext.l.f8757b
        L54:
            java.lang.String r4 = "left"
            java.lang.String r7 = r7.getString(r4)
            if (r7 == 0) goto L6b
            java.util.Locale r4 = java.util.Locale.ROOT
            java.lang.String r7 = r7.toUpperCase(r4)
            t2.j.e(r7, r1)
            com.th3rdwave.safeareacontext.l r7 = com.th3rdwave.safeareacontext.l.valueOf(r7)
            if (r7 != 0) goto L6d
        L6b:
            com.th3rdwave.safeareacontext.l r7 = com.th3rdwave.safeareacontext.l.f8757b
        L6d:
            com.th3rdwave.safeareacontext.m r1 = new com.th3rdwave.safeareacontext.m
            r1.<init>(r0, r2, r3, r7)
            r6.setEdges(r1)
        L75:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.th3rdwave.safeareacontext.SafeAreaViewManager.setEdges(com.th3rdwave.safeareacontext.k, com.facebook.react.bridge.ReadableMap):void");
    }

    @K1.a(name = "mode")
    public final void setMode(k kVar, String str) {
        t2.j.f(kVar, "view");
        if (t2.j.b(str, "padding")) {
            kVar.setMode(o.f8769b);
        } else if (t2.j.b(str, "margin")) {
            kVar.setMode(o.f8770c);
        }
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public Object updateState(com.facebook.react.views.view.g gVar, C0469s0 c0469s0, A0 a02) {
        t2.j.f(gVar, "view");
        ((k) gVar).setStateWrapper(a02);
        return null;
    }

    @Override // com.facebook.react.uimanager.ViewGroupManager, com.facebook.react.uimanager.ViewManager
    public p createShadowNodeInstance() {
        return new p();
    }

    @Override // com.facebook.react.views.view.ReactViewManager, com.facebook.react.uimanager.ViewManager
    public k createViewInstance(B0 b02) {
        t2.j.f(b02, "context");
        return new k(b02);
    }
}
