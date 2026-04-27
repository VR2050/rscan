package com.facebook.react.module.model;

import com.facebook.react.turbomodule.core.interfaces.TurboModule;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class ReactModuleInfo {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f6999g = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f7000a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f7001b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f7002c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f7003d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f7004e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final boolean f7005f;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final boolean a(Class cls) {
            j.f(cls, "clazz");
            return TurboModule.class.isAssignableFrom(cls);
        }

        private a() {
        }
    }

    public ReactModuleInfo(String str, String str2, boolean z3, boolean z4, boolean z5, boolean z6) {
        j.f(str, "name");
        j.f(str2, "className");
        this.f7000a = str;
        this.f7001b = str2;
        this.f7002c = z3;
        this.f7003d = z4;
        this.f7004e = z5;
        this.f7005f = z6;
    }

    public static final boolean b(Class cls) {
        return f6999g.a(cls);
    }

    public final boolean a() {
        return this.f7002c;
    }

    public final String c() {
        return this.f7001b;
    }

    public final boolean d() {
        return this.f7004e;
    }

    public final boolean e() {
        return this.f7005f;
    }

    public final String f() {
        return this.f7000a;
    }

    public final boolean g() {
        return this.f7003d;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ReactModuleInfo(String str, String str2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7) {
        this(str, str2, z3, z4, z6, z7);
        j.f(str, "name");
        j.f(str2, "className");
    }
}
