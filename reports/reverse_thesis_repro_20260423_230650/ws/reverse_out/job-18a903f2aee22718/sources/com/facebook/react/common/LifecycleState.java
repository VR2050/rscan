package com.facebook.react.common;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class LifecycleState {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final LifecycleState f6642b = new LifecycleState("BEFORE_CREATE", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final LifecycleState f6643c = new LifecycleState("BEFORE_RESUME", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final LifecycleState f6644d = new LifecycleState("RESUMED", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ LifecycleState[] f6645e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f6646f;

    static {
        LifecycleState[] lifecycleStateArrA = a();
        f6645e = lifecycleStateArrA;
        f6646f = AbstractC0628a.a(lifecycleStateArrA);
    }

    private LifecycleState(String str, int i3) {
    }

    private static final /* synthetic */ LifecycleState[] a() {
        return new LifecycleState[]{f6642b, f6643c, f6644d};
    }

    public static LifecycleState valueOf(String str) {
        return (LifecycleState) Enum.valueOf(LifecycleState.class, str);
    }

    public static LifecycleState[] values() {
        return (LifecycleState[]) f6645e.clone();
    }
}
