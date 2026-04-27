package com.facebook.react.views.textinput;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

/* JADX INFO: renamed from: com.facebook.react.views.textinput.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0485b extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private float f8218h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private float f8219i;

    public C0485b(int i3, int i4, float f3, float f4) {
        super(i3, i4);
        this.f8218h = f3;
        this.f8219i = f4;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        WritableMap writableMapCreateMap2 = Arguments.createMap();
        writableMapCreateMap2.putDouble("width", this.f8218h);
        writableMapCreateMap2.putDouble("height", this.f8219i);
        writableMapCreateMap.putMap("contentSize", writableMapCreateMap2);
        writableMapCreateMap.putInt("target", o());
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topContentSizeChange";
    }
}
