package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: loaded from: classes.dex */
class G extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f8190h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f8191i;

    public G(int i3, int i4, int i5, int i6) {
        super(i3, i4);
        this.f8190h = i5;
        this.f8191i = i6;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        WritableMap writableMapCreateMap2 = Arguments.createMap();
        writableMapCreateMap2.putInt("end", this.f8191i);
        writableMapCreateMap2.putInt("start", this.f8190h);
        writableMapCreateMap.putMap("selection", writableMapCreateMap2);
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topSelectionChange";
    }
}
