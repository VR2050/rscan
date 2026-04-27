package com.facebook.react.fabric.events;

import com.facebook.jni.HybridData;
import com.facebook.react.fabric.c;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class EventBeatManager implements O1.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final a f6953a = new a(null);
    private final HybridData mHybridData = f6953a.b();

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final HybridData b() {
            return EventBeatManager.initHybrid();
        }

        private a() {
        }
    }

    static {
        c.a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final native HybridData initHybrid();

    private final native void tick();

    @Override // O1.a
    public void a() {
        tick();
    }
}
