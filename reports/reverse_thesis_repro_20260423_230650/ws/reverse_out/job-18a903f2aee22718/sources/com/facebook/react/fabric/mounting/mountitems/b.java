package com.facebook.react.fabric.mounting.mountitems;

import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b implements MountItem {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f6971a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6972b;

    public b(int i3, int i4) {
        this.f6971a = i3;
        this.f6972b = i4;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(m1.d dVar) {
        j.f(dVar, "mountingManager");
        m1.g gVarF = dVar.f(this.f6971a);
        if (gVarF == null) {
            return;
        }
        gVarF.i(this.f6972b);
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.f6971a;
    }
}
