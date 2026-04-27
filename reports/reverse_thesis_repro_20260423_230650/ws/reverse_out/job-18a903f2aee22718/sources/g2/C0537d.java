package g2;

import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: g2.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0537d extends O1.d {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f9217i = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final WritableMap f9218h;

    /* JADX INFO: renamed from: g2.d$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0537d(int i3, WritableMap writableMap) {
        super(i3);
        t2.j.f(writableMap, "mEventData");
        this.f9218h = writableMap;
    }

    @Override // O1.d
    public boolean a() {
        return false;
    }

    @Override // O1.d
    public void c(RCTEventEmitter rCTEventEmitter) {
        t2.j.f(rCTEventEmitter, "rctEventEmitter");
        rCTEventEmitter.receiveEvent(o(), k(), this.f9218h);
    }

    @Override // O1.d
    public short g() {
        return (short) 0;
    }

    @Override // O1.d
    public String k() {
        return "topLoadingFinish";
    }
}
