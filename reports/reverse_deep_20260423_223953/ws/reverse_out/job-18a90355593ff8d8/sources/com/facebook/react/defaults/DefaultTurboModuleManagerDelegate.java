package com.facebook.react.defaults;

import c1.L;
import c1.Q;
import com.facebook.jni.HybridData;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.defaults.DefaultTurboModuleManagerDelegate;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class DefaultTurboModuleManagerDelegate extends Q {
    private static final b Companion = new b(null);

    public static final class a extends Q.a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final List f6686c = new ArrayList();

        /* JADX INFO: Access modifiers changed from: private */
        public static final List g(l lVar, ReactApplicationContext reactApplicationContext) {
            j.f(reactApplicationContext, "context");
            return AbstractC0586n.b(lVar.d(reactApplicationContext));
        }

        public final a f(final l lVar) {
            j.f(lVar, "provider");
            this.f6686c.add(new l() { // from class: com.facebook.react.defaults.h
                @Override // s2.l
                public final Object d(Object obj) {
                    return DefaultTurboModuleManagerDelegate.a.g(lVar, (ReactApplicationContext) obj);
                }
            });
            return this;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // c1.Q.a
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public DefaultTurboModuleManagerDelegate b(ReactApplicationContext reactApplicationContext, List list) {
            j.f(reactApplicationContext, "context");
            j.f(list, "packages");
            List list2 = this.f6686c;
            ArrayList arrayList = new ArrayList();
            Iterator it = list2.iterator();
            while (it.hasNext()) {
                AbstractC0586n.q(arrayList, (Iterable) ((l) it.next()).d(reactApplicationContext));
            }
            return new DefaultTurboModuleManagerDelegate(reactApplicationContext, list, arrayList, null);
        }
    }

    private static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final HybridData initHybrid(List<Object> list) {
            return DefaultTurboModuleManagerDelegate.initHybrid(list);
        }

        private b() {
        }
    }

    static {
        g.f6699a.a();
    }

    public /* synthetic */ DefaultTurboModuleManagerDelegate(ReactApplicationContext reactApplicationContext, List list, List list2, DefaultConstructorMarker defaultConstructorMarker) {
        this(reactApplicationContext, list, list2);
    }

    public static final native HybridData initHybrid(List<Object> list);

    @Override // com.facebook.react.internal.turbomodule.core.TurboModuleManagerDelegate
    protected HybridData initHybrid() {
        throw new UnsupportedOperationException("DefaultTurboModuleManagerDelegate.initHybrid() must never be called!");
    }

    private DefaultTurboModuleManagerDelegate(ReactApplicationContext reactApplicationContext, List<? extends L> list, List<Object> list2) {
        super(reactApplicationContext, list, Companion.initHybrid(list2));
    }
}
