package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: loaded from: classes.dex */
class I extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private String f8197h;

    public I(int i3, int i4, String str) {
        super(i3, i4);
        this.f8197h = str;
    }

    @Override // O1.d
    public boolean a() {
        return false;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putInt("target", o());
        writableMapCreateMap.putString("text", this.f8197h);
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topSubmitEditing";
    }
}
