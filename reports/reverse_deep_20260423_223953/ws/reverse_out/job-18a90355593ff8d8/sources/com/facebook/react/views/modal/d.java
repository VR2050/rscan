package com.facebook.react.views.modal;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d extends O1.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final a f7862h = new a(null);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public d(int i3, int i4) {
        super(i3, i4);
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        j.e(writableMapCreateMap, "createMap(...)");
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topRequestClose";
    }
}
