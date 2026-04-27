package com.facebook.react.modules.core;

import A1.c;
import com.facebook.fbreact.specs.NativeTimingSpec;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.WritableArray;
import j1.e;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "Timing")
public final class TimingModule extends NativeTimingSpec implements c {
    public static final a Companion = new a(null);
    public static final String NAME = "Timing";
    private final JavaTimerManager javaTimerManager;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public TimingModule(ReactApplicationContext reactApplicationContext, e eVar) {
        super(reactApplicationContext);
        j.f(reactApplicationContext, "reactContext");
        j.f(eVar, "devSupportManager");
        this.javaTimerManager = new JavaTimerManager(reactApplicationContext, this, b.f7042f.a(), eVar);
    }

    @Override // A1.c
    public void callIdleCallbacks(double d3) {
        JSTimers jSTimers;
        ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
        if (reactApplicationContextIfActiveOrWarn == null || (jSTimers = (JSTimers) reactApplicationContextIfActiveOrWarn.getJSModule(JSTimers.class)) == null) {
            return;
        }
        jSTimers.callIdleCallbacks(d3);
    }

    @Override // A1.c
    public void callTimers(WritableArray writableArray) {
        JSTimers jSTimers;
        j.f(writableArray, "timerIDs");
        ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
        if (reactApplicationContextIfActiveOrWarn == null || (jSTimers = (JSTimers) reactApplicationContextIfActiveOrWarn.getJSModule(JSTimers.class)) == null) {
            return;
        }
        jSTimers.callTimers(writableArray);
    }

    @Override // com.facebook.fbreact.specs.NativeTimingSpec
    public void createTimer(double d3, double d4, double d5, boolean z3) {
        this.javaTimerManager.t((int) d3, (int) d4, d5, z3);
    }

    @Override // com.facebook.fbreact.specs.NativeTimingSpec
    public void deleteTimer(double d3) {
        this.javaTimerManager.deleteTimer((int) d3);
    }

    @Override // A1.c
    public void emitTimeDriftWarning(String str) {
        JSTimers jSTimers;
        j.f(str, "warningMessage");
        ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
        if (reactApplicationContextIfActiveOrWarn == null || (jSTimers = (JSTimers) reactApplicationContextIfActiveOrWarn.getJSModule(JSTimers.class)) == null) {
            return;
        }
        jSTimers.emitTimeDriftWarning(str);
    }

    public final boolean hasActiveTimersInRange(long j3) {
        return this.javaTimerManager.u(j3);
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void invalidate() {
        this.javaTimerManager.x();
    }

    @Override // com.facebook.fbreact.specs.NativeTimingSpec
    public void setSendIdleEvents(boolean z3) {
        this.javaTimerManager.setSendIdleEvents(z3);
    }
}
