package M;

import java.lang.reflect.InvocationHandler;
import java.util.concurrent.Callable;
import org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class c extends L.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private JsReplyProxyBoundaryInterface f1748a;

    class a implements Callable {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ JsReplyProxyBoundaryInterface f1749a;

        a(JsReplyProxyBoundaryInterface jsReplyProxyBoundaryInterface) {
            this.f1749a = jsReplyProxyBoundaryInterface;
        }

        @Override // java.util.concurrent.Callable
        public Object call() {
            return new c(this.f1749a);
        }
    }

    public c(JsReplyProxyBoundaryInterface jsReplyProxyBoundaryInterface) {
        this.f1748a = jsReplyProxyBoundaryInterface;
    }

    public static c a(InvocationHandler invocationHandler) {
        JsReplyProxyBoundaryInterface jsReplyProxyBoundaryInterface = (JsReplyProxyBoundaryInterface) S2.a.a(JsReplyProxyBoundaryInterface.class, invocationHandler);
        return (c) jsReplyProxyBoundaryInterface.getOrCreatePeer(new a(jsReplyProxyBoundaryInterface));
    }
}
