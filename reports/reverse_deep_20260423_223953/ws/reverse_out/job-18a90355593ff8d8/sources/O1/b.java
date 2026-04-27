package O1;

import com.facebook.react.uimanager.events.EventDispatcher;
import com.facebook.react.uimanager.events.RCTEventEmitter;
import com.facebook.react.uimanager.events.RCTModernEventEmitter;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class b implements EventDispatcher {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2035b = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final EventDispatcher f2036c = new b();

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final EventDispatcher a() {
            return b.f2036c;
        }

        private a() {
        }
    }

    private b() {
    }

    public static final EventDispatcher k() {
        return f2035b.a();
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void a(int i3, RCTEventEmitter rCTEventEmitter) {
        t2.j.f(rCTEventEmitter, "eventEmitter");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void c(int i3, RCTModernEventEmitter rCTModernEventEmitter) {
        t2.j.f(rCTModernEventEmitter, "eventEmitter");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void d(g gVar) {
        t2.j.f(gVar, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void f(O1.a aVar) {
        t2.j.f(aVar, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void g(d dVar) {
        t2.j.f(dVar, "event");
        Y.a.b("BlackHoleEventDispatcher", "Trying to emit event to JS, but the React instance isn't ready. Event: " + dVar.k());
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void i(O1.a aVar) {
        t2.j.f(aVar, "listener");
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void b() {
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void h() {
    }

    @Override // com.facebook.react.uimanager.events.EventDispatcher
    public void e(int i3) {
    }
}
