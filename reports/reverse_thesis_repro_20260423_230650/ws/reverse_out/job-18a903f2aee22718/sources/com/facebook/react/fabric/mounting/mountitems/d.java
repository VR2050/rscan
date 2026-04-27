package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReadableArray;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6974b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6975c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f6976d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ReadableArray f6977e;

    public d(int i3, int i4, int i5, ReadableArray readableArray) {
        this.f6974b = i3;
        this.f6975c = i4;
        this.f6976d = i5;
        this.f6977e = readableArray;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(m1.d dVar) {
        j.f(dVar, "mountingManager");
        dVar.o(this.f6974b, this.f6975c, this.f6976d, this.f6977e);
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.f6974b;
    }

    public String toString() {
        return "DispatchIntCommandMountItem [" + this.f6975c + "] " + this.f6976d;
    }
}
