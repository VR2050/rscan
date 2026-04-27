package com.facebook.react.views.view;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final a f8314h = new a(null);

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public j(int i3, int i4) {
        super(i3, i4);
    }

    @Override // O1.d
    public boolean a() {
        return false;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        t2.j.e(writableMapCreateMap, "createMap(...)");
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topClick";
    }
}
