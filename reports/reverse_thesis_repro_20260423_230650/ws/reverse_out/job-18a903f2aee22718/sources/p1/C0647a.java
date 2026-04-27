package p1;

import android.view.Choreographer;
import com.facebook.react.bridge.UiThreadUtil;
import p1.InterfaceC0648b;
import t2.j;

/* JADX INFO: renamed from: p1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0647a implements InterfaceC0648b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0647a f9842a = new C0647a();

    /* JADX INFO: renamed from: p1.a$a, reason: collision with other inner class name */
    private static final class C0147a implements InterfaceC0648b.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Choreographer f9843a;

        public C0147a() {
            Choreographer choreographer = Choreographer.getInstance();
            j.e(choreographer, "getInstance(...)");
            this.f9843a = choreographer;
        }

        @Override // p1.InterfaceC0648b.a
        public void a(Choreographer.FrameCallback frameCallback) {
            j.f(frameCallback, "callback");
            this.f9843a.postFrameCallback(frameCallback);
        }

        @Override // p1.InterfaceC0648b.a
        public void b(Choreographer.FrameCallback frameCallback) {
            j.f(frameCallback, "callback");
            this.f9843a.removeFrameCallback(frameCallback);
        }
    }

    private C0647a() {
    }

    public static final C0647a b() {
        return f9842a;
    }

    @Override // p1.InterfaceC0648b
    public InterfaceC0648b.a a() {
        UiThreadUtil.assertOnUiThread();
        return new C0147a();
    }
}
