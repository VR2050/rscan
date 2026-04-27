package com.facebook.react.views.safeareaview;

import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.C0271j0;
import androidx.core.view.E;
import androidx.core.view.V;
import com.facebook.react.bridge.GuardedRunnable;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.UIManagerModule;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b extends ViewGroup {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final B0 f7875b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private A0 f7876c;

    public static final class a extends GuardedRunnable {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ androidx.core.graphics.b f7878c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(androidx.core.graphics.b bVar, B0 b02) {
            super(b02);
            this.f7878c = bVar;
        }

        @Override // com.facebook.react.bridge.GuardedRunnable
        public void runGuarded() {
            UIManagerModule uIManagerModule = (UIManagerModule) b.this.getReactContext().b().getNativeModule(UIManagerModule.class);
            if (uIManagerModule != null) {
                int id = b.this.getId();
                androidx.core.graphics.b bVar = this.f7878c;
                uIManagerModule.updateInsetsPadding(id, bVar.f4322b, bVar.f4321a, bVar.f4324d, bVar.f4323c);
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(B0 b02) {
        super(b02);
        j.f(b02, "reactContext");
        this.f7875b = b02;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0271j0 b(b bVar, View view, C0271j0 c0271j0) {
        j.f(view, "<unused var>");
        j.f(c0271j0, "windowInsets");
        androidx.core.graphics.b bVarF = c0271j0.f(C0271j0.m.e() | C0271j0.m.a());
        j.e(bVarF, "getInsets(...)");
        bVar.c(bVarF);
        return C0271j0.f4470b;
    }

    private final void c(androidx.core.graphics.b bVar) {
        A0 a02 = this.f7876c;
        if (a02 == null) {
            B0 b02 = this.f7875b;
            b02.runOnNativeModulesQueueThread(new a(bVar, b02));
            return;
        }
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        C0444f0 c0444f0 = C0444f0.f7603a;
        writableNativeMap.putDouble("left", c0444f0.d(bVar.f4321a));
        writableNativeMap.putDouble("top", c0444f0.d(bVar.f4322b));
        writableNativeMap.putDouble("bottom", c0444f0.d(bVar.f4324d));
        writableNativeMap.putDouble("right", c0444f0.d(bVar.f4323c));
        a02.b(writableNativeMap);
    }

    public final B0 getReactContext() {
        return this.f7875b;
    }

    public final A0 getStateWrapper$ReactAndroid_release() {
        return this.f7876c;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        V.i0(this, new E() { // from class: com.facebook.react.views.safeareaview.a
            @Override // androidx.core.view.E
            public final C0271j0 a(View view, C0271j0 c0271j0) {
                return b.b(this.f7874a, view, c0271j0);
            }
        });
        requestApplyInsets();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
    }

    public final void setStateWrapper$ReactAndroid_release(A0 a02) {
        this.f7876c = a02;
    }
}
