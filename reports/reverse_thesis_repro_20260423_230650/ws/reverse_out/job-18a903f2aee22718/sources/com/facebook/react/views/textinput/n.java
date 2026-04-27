package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: loaded from: classes.dex */
class n extends O1.d {
    public n(int i3, int i4) {
        super(i3, i4);
    }

    @Override // O1.d
    public boolean a() {
        return false;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putInt("target", o());
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topBlur";
    }
}
