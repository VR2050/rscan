package com.th3rdwave.safeareacontext;

import android.R;
import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import com.facebook.react.bridge.ReactApplicationContext;
import i2.D;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "RNCSafeAreaContext")
public final class SafeAreaContextModule extends NativeSafeAreaContextSpec {
    public static final a Companion = new a(null);
    public static final String NAME = "RNCSafeAreaContext";

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public SafeAreaContextModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    private final Map<String, Object> getInitialWindowMetrics() {
        View viewFindViewById;
        Window window;
        Activity currentActivity = getReactApplicationContext().getCurrentActivity();
        ViewGroup viewGroup = (ViewGroup) ((currentActivity == null || (window = currentActivity.getWindow()) == null) ? null : window.getDecorView());
        if (viewGroup == null || (viewFindViewById = viewGroup.findViewById(R.id.content)) == null) {
            return null;
        }
        com.th3rdwave.safeareacontext.a aVarE = h.e(viewGroup);
        c cVarA = h.a(viewGroup, viewFindViewById);
        if (aVarE == null || cVarA == null) {
            return null;
        }
        return D.h(h2.n.a("insets", q.a(aVarE)), h2.n.a("frame", q.c(cVarA)));
    }

    @Override // com.th3rdwave.safeareacontext.NativeSafeAreaContextSpec, com.facebook.react.bridge.NativeModule
    public String getName() {
        return "RNCSafeAreaContext";
    }

    @Override // com.th3rdwave.safeareacontext.NativeSafeAreaContextSpec
    public Map<String, Object> getTypedExportedConstants() {
        return D.d(h2.n.a("initialWindowMetrics", getInitialWindowMetrics()));
    }
}
