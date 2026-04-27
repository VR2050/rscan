package com.th3rdwave.safeareacontext;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class b extends O1.d {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f8737j = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final com.th3rdwave.safeareacontext.a f8738h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final c f8739i;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(int i3, int i4, com.th3rdwave.safeareacontext.a aVar, c cVar) {
        super(i3, i4);
        t2.j.f(aVar, "mInsets");
        t2.j.f(cVar, "mFrame");
        this.f8738h = aVar;
        this.f8739i = cVar;
    }

    @Override // O1.d
    protected WritableMap j() {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putMap("insets", q.b(this.f8738h));
        writableMapCreateMap.putMap("frame", q.d(this.f8739i));
        return writableMapCreateMap;
    }

    @Override // O1.d
    public String k() {
        return "topInsetsChange";
    }
}
