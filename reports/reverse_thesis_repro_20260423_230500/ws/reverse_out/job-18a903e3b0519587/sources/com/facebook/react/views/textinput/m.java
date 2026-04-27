package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: loaded from: classes.dex */
public class m extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private String f8271h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f8272i;

    public m(int i3, int i4, String str, int i5) {
        super(i3, i4);
        this.f8271h = str;
        this.f8272i = i5;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("text", this.f8271h);
        writableMapCreateMap.putInt("eventCount", this.f8272i);
        writableMapCreateMap.putInt("target", o());
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topChange";
    }
}
