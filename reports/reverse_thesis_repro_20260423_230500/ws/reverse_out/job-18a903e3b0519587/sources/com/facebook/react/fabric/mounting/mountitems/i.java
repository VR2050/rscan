package com.facebook.react.fabric.mounting.mountitems;

import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.RetryableMountingLayerException;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class i implements MountItem {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f6991a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6992b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6993c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f6994d = "Fabric.SendAccessibilityEvent";

    public i(int i3, int i4, int i5) {
        this.f6991a = i3;
        this.f6992b = i4;
        this.f6993c = i5;
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public void execute(m1.d dVar) {
        j.f(dVar, "mountingManager");
        try {
            dVar.q(this.f6991a, this.f6992b, this.f6993c);
        } catch (RetryableMountingLayerException e3) {
            ReactSoftExceptionLogger.logSoftException(this.f6994d, e3);
        }
    }

    @Override // com.facebook.react.fabric.mounting.mountitems.MountItem
    public int getSurfaceId() {
        return this.f6991a;
    }

    public String toString() {
        return "SendAccessibilityEventMountItem [" + this.f6992b + "] " + this.f6993c;
    }
}
