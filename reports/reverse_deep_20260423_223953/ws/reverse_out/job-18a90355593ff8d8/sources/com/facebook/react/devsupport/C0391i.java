package com.facebook.react.devsupport;

import android.content.Context;
import f1.C0527a;
import j1.InterfaceC0593b;
import j1.InterfaceC0594c;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.react.devsupport.i, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0391i implements H {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final a f6849a = new a(null);

    /* JADX INFO: renamed from: com.facebook.react.devsupport.i$a */
    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    @Override // com.facebook.react.devsupport.H
    public j1.e a(Context context, c0 c0Var, String str, boolean z3, j1.i iVar, InterfaceC0593b interfaceC0593b, int i3, Map map, d1.k kVar, InterfaceC0594c interfaceC0594c, j1.h hVar, boolean z4) {
        t2.j.f(context, "applicationContext");
        t2.j.f(c0Var, "reactInstanceManagerHelper");
        return !z4 ? C0527a.f9200d ? new b0(context) : new k0() : new C0383a(context, c0Var, str, z3, iVar, interfaceC0593b, i3, map, kVar, interfaceC0594c, hVar);
    }

    @Override // com.facebook.react.devsupport.H
    public j1.e b(Context context, c0 c0Var, String str, boolean z3, j1.i iVar, InterfaceC0593b interfaceC0593b, int i3, Map map, d1.k kVar, InterfaceC0594c interfaceC0594c, j1.h hVar) {
        t2.j.f(context, "applicationContext");
        t2.j.f(c0Var, "reactInstanceManagerHelper");
        if (!z3) {
            return new k0();
        }
        try {
            String str2 = "com.facebook.react.devsupport.BridgeDevSupportManager";
            t2.j.e(str2, "toString(...)");
            Object objNewInstance = Class.forName(str2).getConstructor(Context.class, c0.class, String.class, Boolean.TYPE, j1.i.class, InterfaceC0593b.class, Integer.TYPE, Map.class, d1.k.class, InterfaceC0594c.class, j1.h.class).newInstance(context, c0Var, str, Boolean.TRUE, iVar, interfaceC0593b, Integer.valueOf(i3), map, kVar, interfaceC0594c, hVar);
            t2.j.d(objNewInstance, "null cannot be cast to non-null type com.facebook.react.devsupport.interfaces.DevSupportManager");
            return (j1.e) objNewInstance;
        } catch (Exception unused) {
            return new b0(context);
        }
    }
}
