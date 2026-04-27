package com.facebook.react.modules.fresco;

import B2.w;
import B2.z;
import D1.c;
import D1.d;
import I0.C0194t;
import I0.C0195u;
import I0.EnumC0189n;
import android.content.Context;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.modules.network.g;
import com.facebook.react.modules.network.h;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import java.util.HashSet;
import kotlin.jvm.internal.DefaultConstructorMarker;
import l0.AbstractC0616d;
import l0.C0614b;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = FrescoModule.NAME, needsEagerInit = true)
public class FrescoModule extends ReactContextBaseJavaModule implements LifecycleEventListener, TurboModule {
    public static final a Companion = new a(null);
    public static final String NAME = "FrescoModule";
    private static boolean hasBeenInitialized;
    private final boolean clearOnDestroy;
    private C0195u config;
    private C0194t pipeline;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final C0195u b(ReactContext reactContext) {
            return c(reactContext).a();
        }

        public final C0195u.a c(ReactContext reactContext) {
            j.f(reactContext, "context");
            HashSet hashSet = new HashSet();
            hashSet.add(new d());
            z zVarA = g.a();
            h.a(zVarA).d(new w(new com.facebook.react.modules.network.d()));
            Context applicationContext = reactContext.getApplicationContext();
            j.e(applicationContext, "getApplicationContext(...)");
            C0195u.a aVarT = E0.a.a(applicationContext, zVarA).S(new c(zVarA)).R(EnumC0189n.f1225c).T(hashSet);
            aVarT.b().d(true);
            return aVarT;
        }

        public final boolean d() {
            return FrescoModule.hasBeenInitialized;
        }

        private a() {
        }
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext) {
        this(reactApplicationContext, false, null, 6, null);
    }

    public static final C0195u.a getDefaultConfigBuilder(ReactContext reactContext) {
        return Companion.c(reactContext);
    }

    private final C0194t getImagePipeline() {
        if (this.pipeline == null) {
            this.pipeline = AbstractC0616d.a();
        }
        return this.pipeline;
    }

    public static final boolean hasBeenInitialized() {
        return Companion.d();
    }

    public void clearSensitiveData() {
        C0194t imagePipeline = getImagePipeline();
        if (imagePipeline != null) {
            imagePipeline.c();
        }
    }

    @Override // com.facebook.react.bridge.NativeModule
    public String getName() {
        return NAME;
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void initialize() {
        super.initialize();
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        reactApplicationContext.addLifecycleEventListener(this);
        a aVar = Companion;
        if (!aVar.d()) {
            C0195u c0195uB = this.config;
            if (c0195uB == null) {
                j.c(reactApplicationContext);
                c0195uB = aVar.b(reactApplicationContext);
            }
            C0614b.a aVarE = C0614b.e();
            j.e(aVarE, "newBuilder(...)");
            AbstractC0616d.c(reactApplicationContext.getApplicationContext(), c0195uB, aVarE.e());
            hasBeenInitialized = true;
        } else if (this.config != null) {
            Y.a.I("ReactNative", "Fresco has already been initialized with a different config. The new Fresco configuration will be ignored!");
        }
        this.config = null;
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void invalidate() {
        getReactApplicationContext().removeLifecycleEventListener(this);
        super.invalidate();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        C0194t imagePipeline;
        if (Companion.d() && this.clearOnDestroy && (imagePipeline = getImagePipeline()) != null) {
            imagePipeline.e();
        }
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext, C0194t c0194t) {
        this(reactApplicationContext, c0194t, false, false, 12, null);
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext, C0194t c0194t, boolean z3) {
        this(reactApplicationContext, c0194t, z3, false, 8, null);
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext, boolean z3) {
        this(reactApplicationContext, z3, null, 4, null);
    }

    public /* synthetic */ FrescoModule(ReactApplicationContext reactApplicationContext, boolean z3, C0195u c0195u, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(reactApplicationContext, (i3 & 2) != 0 ? true : z3, (i3 & 4) != 0 ? null : c0195u);
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext, boolean z3, C0195u c0195u) {
        super(reactApplicationContext);
        this.clearOnDestroy = z3;
        this.config = c0195u;
    }

    public /* synthetic */ FrescoModule(ReactApplicationContext reactApplicationContext, C0194t c0194t, boolean z3, boolean z4, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(reactApplicationContext, c0194t, (i3 & 4) != 0 ? true : z3, (i3 & 8) != 0 ? false : z4);
    }

    public FrescoModule(ReactApplicationContext reactApplicationContext, C0194t c0194t, boolean z3, boolean z4) {
        this(reactApplicationContext, z3, null, 4, null);
        this.pipeline = c0194t;
        if (z4) {
            hasBeenInitialized = true;
        }
    }
}
