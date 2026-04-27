package com.th3rdwave.safeareacontext;

import android.view.View;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.ViewGroupManager;
import com.facebook.react.uimanager.W0;
import i2.D;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = SafeAreaProviderManager.REACT_CLASS)
public final class SafeAreaProviderManager extends ViewGroupManager<f> implements W0 {
    public static final a Companion = new a(null);
    public static final String REACT_CLASS = "RNCSafeAreaProvider";
    private final T1.m mDelegate = new T1.m(this);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* synthetic */ class b extends t2.i implements s2.q {

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        public static final b f8732k = new b();

        b() {
            super(3, g.class, "handleOnInsetsChange", "handleOnInsetsChange(Lcom/th3rdwave/safeareacontext/SafeAreaProvider;Lcom/th3rdwave/safeareacontext/EdgeInsets;Lcom/th3rdwave/safeareacontext/Rect;)V", 1);
        }

        @Override // s2.q
        public /* bridge */ /* synthetic */ Object a(Object obj, Object obj2, Object obj3) {
            k((f) obj, (com.th3rdwave.safeareacontext.a) obj2, (c) obj3);
            return h2.r.f9288a;
        }

        public final void k(f fVar, com.th3rdwave.safeareacontext.a aVar, c cVar) {
            t2.j.f(fVar, "p0");
            t2.j.f(aVar, "p1");
            t2.j.f(cVar, "p2");
            g.b(fVar, aVar, cVar);
        }
    }

    @Override // com.facebook.react.uimanager.BaseViewManager, com.facebook.react.uimanager.ViewManager
    public Map<String, Map<String, String>> getExportedCustomDirectEventTypeConstants() {
        return D.i(h2.n.a("topInsetsChange", D.i(h2.n.a("registrationName", "onInsetsChange"))));
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
    public void addEventEmitters(B0 b02, f fVar) {
        t2.j.f(b02, "reactContext");
        t2.j.f(fVar, "view");
        super.addEventEmitters(b02, fVar);
        fVar.setOnInsetsChangeHandler(b.f8732k);
    }

    @Override // com.facebook.react.uimanager.ViewManager
    public f createViewInstance(B0 b02) {
        t2.j.f(b02, "context");
        return new f(b02);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.facebook.react.uimanager.ViewManager
    public T1.m getDelegate() {
        return this.mDelegate;
    }
}
