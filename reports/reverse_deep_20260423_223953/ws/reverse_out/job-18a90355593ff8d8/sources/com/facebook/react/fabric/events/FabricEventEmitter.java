package com.facebook.react.fabric.events;

import O1.q;
import c2.C0353a;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.fabric.FabricUIManager;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class FabricEventEmitter implements RCTModernEventEmitter {
    private final FabricUIManager uiManager;

    public FabricEventEmitter(FabricUIManager fabricUIManager) {
        j.f(fabricUIManager, "uiManager");
        this.uiManager = fabricUIManager;
    }

    @Override // com.facebook.react.uimanager.events.RCTEventEmitter
    public void receiveEvent(int i3, String str, WritableMap writableMap) {
        j.f(str, "eventName");
        receiveEvent(-1, i3, str, writableMap);
    }

    @Override // com.facebook.react.uimanager.events.RCTEventEmitter
    public void receiveTouches(String str, WritableArray writableArray, WritableArray writableArray2) {
        j.f(str, "eventName");
        j.f(writableArray, "touches");
        j.f(writableArray2, "changedIndices");
        throw new UnsupportedOperationException("EventEmitter#receiveTouches is not supported by Fabric");
    }

    @Override // com.facebook.react.uimanager.events.RCTModernEventEmitter
    public void receiveEvent(int i3, int i4, String str, WritableMap writableMap) {
        j.f(str, "eventName");
        receiveEvent(i3, i4, str, false, 0, writableMap, 2);
    }

    @Override // com.facebook.react.uimanager.events.RCTModernEventEmitter
    public void receiveTouches(q qVar) {
        j.f(qVar, "event");
        throw new UnsupportedOperationException("EventEmitter#receiveTouches is not supported by Fabric");
    }

    @Override // com.facebook.react.uimanager.events.RCTModernEventEmitter
    public void receiveEvent(int i3, int i4, String str, boolean z3, int i5, WritableMap writableMap, int i6) {
        j.f(str, "eventName");
        C0353a.c(0L, "FabricEventEmitter.receiveEvent('" + str + "')");
        try {
            this.uiManager.receiveEvent(i3, i4, str, z3, writableMap, i6);
        } finally {
            C0353a.i(0L);
        }
    }
}
