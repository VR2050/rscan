package com.facebook.react.devsupport;

import android.content.Context;
import com.facebook.react.bridge.UiThreadUtil;
import j1.InterfaceC0593b;
import j1.InterfaceC0594c;
import java.util.Map;

/* JADX INFO: renamed from: com.facebook.react.devsupport.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0383a extends E {
    public C0383a(Context context, c0 c0Var, String str, boolean z3, j1.i iVar, InterfaceC0593b interfaceC0593b, int i3, Map map, d1.k kVar, InterfaceC0594c interfaceC0594c, j1.h hVar) {
        super(context, c0Var, str, z3, iVar, interfaceC0593b, i3, map, kVar, interfaceC0594c, hVar);
    }

    @Override // com.facebook.react.devsupport.E
    protected String k0() {
        return "Bridgeless";
    }

    @Override // j1.e
    public void r() {
        UiThreadUtil.assertOnUiThread();
        o();
        this.f6729f.j("BridgelessDevSupportManager.handleReloadJS()");
    }
}
