package com.facebook.react.views.text;

import com.facebook.react.uimanager.C0467r0;

/* JADX INFO: loaded from: classes.dex */
public class d extends C0467r0 {

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private String f8073y = null;

    @Override // com.facebook.react.uimanager.C0467r0, com.facebook.react.uimanager.InterfaceC0466q0
    public boolean R() {
        return true;
    }

    @K1.a(name = "text")
    public void setText(String str) {
        this.f8073y = str;
        y0();
    }

    @Override // com.facebook.react.uimanager.C0467r0
    public String toString() {
        return v() + " [text: " + this.f8073y + "]";
    }

    public String v1() {
        return this.f8073y;
    }
}
