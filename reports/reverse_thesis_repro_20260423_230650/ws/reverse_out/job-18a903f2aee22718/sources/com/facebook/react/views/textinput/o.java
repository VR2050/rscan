package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: loaded from: classes.dex */
class o extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private String f8273h;

    public o(int i3, int i4, String str) {
        super(i3, i4);
        this.f8273h = str;
    }

    @Override // O1.d
    public boolean a() {
        return false;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putInt("target", o());
        writableMapCreateMap.putString("text", this.f8273h);
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topEndEditing";
    }
}
