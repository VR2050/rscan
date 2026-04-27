package com.facebook.hermes.reactexecutor;

import com.facebook.jni.HybridData;
import com.facebook.react.bridge.JavaScriptExecutor;
import com.facebook.soloader.SoLoader;
import f1.C0527a;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class HermesExecutor extends JavaScriptExecutor {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f6042a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static String f6043b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final HybridData initHybrid(boolean z3, String str, long j3) {
            return HermesExecutor.initHybrid(z3, str, j3);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final HybridData initHybridDefaultConfig(boolean z3, String str) {
            return HermesExecutor.initHybridDefaultConfig(z3, str);
        }

        public final void b() {
            if (HermesExecutor.f6043b == null) {
                SoLoader.t("hermes");
                SoLoader.t("hermes_executor");
                HermesExecutor.f6043b = C0527a.f9198b ? "Debug" : "Release";
            }
        }

        private a() {
        }
    }

    static {
        a aVar = new a(null);
        f6042a = aVar;
        aVar.b();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public HermesExecutor(boolean z3, String str) {
        super(f6042a.initHybridDefaultConfig(z3, str));
        j.f(str, "debuggerName");
    }

    public static final void e() {
        f6042a.b();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final native HybridData initHybrid(boolean z3, String str, long j3);

    /* JADX INFO: Access modifiers changed from: private */
    public static final native HybridData initHybridDefaultConfig(boolean z3, String str);

    @Override // com.facebook.react.bridge.JavaScriptExecutor
    public String getName() {
        return "HermesExecutor" + f6043b;
    }
}
