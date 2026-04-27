package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.fabric.FabricUIManager;
import com.facebook.react.uimanager.A0;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class h implements MountItem {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f6985a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6986b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ReadableMap f6987c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final A0 f6988d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f6989e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f6990f;

    public h(int i3, int i4, String str, ReadableMap readableMap, A0 a02, boolean z3) {
        j.f(str, "component");
        this.f6985a = i3;
        this.f6986b = i4;
        this.f6987c = readableMap;
        this.f6988d = a02;
        this.f6989e = z3;
        this.f6990f = f.a(str);
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(m1.d dVar) {
        j.f(dVar, "mountingManager");
        m1.g gVarF = dVar.f(this.f6985a);
        if (gVarF != null) {
            gVarF.A(this.f6990f, this.f6986b, this.f6987c, this.f6988d, this.f6989e);
            return;
        }
        Y.a.m(FabricUIManager.TAG, "Skipping View PreAllocation; no SurfaceMountingManager found for [" + this.f6985a + "]");
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.f6985a;
    }

    public String toString() {
        String string;
        String string2;
        StringBuilder sb = new StringBuilder("PreAllocateViewMountItem [");
        sb.append(this.f6986b);
        sb.append("] - component: ");
        sb.append(this.f6990f);
        sb.append(" surfaceId: ");
        sb.append(this.f6985a);
        sb.append(" isLayoutable: ");
        sb.append(this.f6989e);
        if (FabricUIManager.IS_DEVELOPMENT_ENVIRONMENT) {
            sb.append(" props: ");
            ReadableMap readableMap = this.f6987c;
            String str = "<null>";
            if (readableMap == null || (string = readableMap.toString()) == null) {
                string = "<null>";
            }
            sb.append(string);
            sb.append(" state: ");
            A0 a02 = this.f6988d;
            if (a02 != null && (string2 = a02.toString()) != null) {
                str = string2;
            }
            sb.append(str);
        }
        String string3 = sb.toString();
        j.e(string3, "toString(...)");
        return string3;
    }
}
