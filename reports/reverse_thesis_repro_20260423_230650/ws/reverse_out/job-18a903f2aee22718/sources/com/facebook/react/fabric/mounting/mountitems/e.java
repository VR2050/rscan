package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReadableArray;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e extends c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6978b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6979c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f6980d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ReadableArray f6981e;

    public e(int i3, int i4, String str, ReadableArray readableArray) {
        j.f(str, "commandId");
        this.f6978b = i3;
        this.f6979c = i4;
        this.f6980d = str;
        this.f6981e = readableArray;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(m1.d dVar) {
        j.f(dVar, "mountingManager");
        dVar.p(this.f6978b, this.f6979c, this.f6980d, this.f6981e);
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.f6978b;
    }

    public String toString() {
        return "DispatchStringCommandMountItem [" + this.f6979c + "] " + this.f6980d;
    }
}
