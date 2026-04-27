package com.facebook.react.devsupport;

import B2.B;
import B2.z;
import android.os.Handler;
import android.os.Looper;
import com.facebook.jni.HybridData;
import java.io.Closeable;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
class CxxInspectorPackagerConnection implements M {
    private final HybridData mHybridData;

    private static class DelegateImpl {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final B2.z f6704a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Handler f6705b;

        class a extends B2.I {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ WebSocketDelegate f6706a;

            /* JADX INFO: renamed from: com.facebook.react.devsupport.CxxInspectorPackagerConnection$DelegateImpl$a$a, reason: collision with other inner class name */
            class RunnableC0103a implements Runnable {

                /* JADX INFO: renamed from: b, reason: collision with root package name */
                final /* synthetic */ Throwable f6708b;

                RunnableC0103a(Throwable th) {
                    this.f6708b = th;
                }

                @Override // java.lang.Runnable
                public void run() {
                    String message = this.f6708b.getMessage();
                    WebSocketDelegate webSocketDelegate = a.this.f6706a;
                    if (message == null) {
                        message = "<Unknown error>";
                    }
                    webSocketDelegate.didFailWithError(null, message);
                    a.this.f6706a.close();
                }
            }

            class b implements Runnable {

                /* JADX INFO: renamed from: b, reason: collision with root package name */
                final /* synthetic */ String f6710b;

                b(String str) {
                    this.f6710b = str;
                }

                @Override // java.lang.Runnable
                public void run() {
                    a.this.f6706a.didReceiveMessage(this.f6710b);
                }
            }

            class c implements Runnable {
                c() {
                }

                @Override // java.lang.Runnable
                public void run() {
                    a.this.f6706a.didOpen();
                }
            }

            class d implements Runnable {
                d() {
                }

                @Override // java.lang.Runnable
                public void run() {
                    a.this.f6706a.didClose();
                    a.this.f6706a.close();
                }
            }

            a(WebSocketDelegate webSocketDelegate) {
                this.f6706a = webSocketDelegate;
            }

            @Override // B2.I
            public void a(B2.H h3, int i3, String str) {
                DelegateImpl.this.scheduleCallback(new d(), 0L);
            }

            @Override // B2.I
            public void c(B2.H h3, Throwable th, B2.D d3) {
                DelegateImpl.this.scheduleCallback(new RunnableC0103a(th), 0L);
            }

            @Override // B2.I
            public void e(B2.H h3, String str) {
                DelegateImpl.this.scheduleCallback(new b(str), 0L);
            }

            @Override // B2.I
            public void f(B2.H h3, B2.D d3) {
                DelegateImpl.this.scheduleCallback(new c(), 0L);
            }
        }

        class b implements a {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ B2.H f6714b;

            b(B2.H h3) {
                this.f6714b = h3;
            }

            @Override // java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                this.f6714b.b(1000, "End of session");
            }
        }

        public a connectWebSocket(String str, WebSocketDelegate webSocketDelegate) {
            return new b(this.f6704a.D(new B.a().m(str).b(), new a(webSocketDelegate)));
        }

        public void scheduleCallback(Runnable runnable, long j3) {
            this.f6705b.postDelayed(runnable, j3);
        }

        private DelegateImpl() {
            z.a aVar = new z.a();
            TimeUnit timeUnit = TimeUnit.SECONDS;
            this.f6704a = aVar.f(10L, timeUnit).W(10L, timeUnit).S(0L, TimeUnit.MINUTES).c();
            this.f6705b = new Handler(Looper.getMainLooper());
        }
    }

    private static class WebSocketDelegate implements Closeable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final HybridData f6716b;

        private WebSocketDelegate(HybridData hybridData) {
            this.f6716b = hybridData;
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            this.f6716b.resetNative();
        }

        public native void didClose();

        public native void didFailWithError(Integer num, String str);

        public native void didOpen();

        public native void didReceiveMessage(String str);
    }

    private interface a extends Closeable {
    }

    static {
        I.a();
    }

    public CxxInspectorPackagerConnection(String str, String str2, String str3) {
        this.mHybridData = initHybrid(str, str2, str3, new DelegateImpl());
    }

    private static native HybridData initHybrid(String str, String str2, String str3, DelegateImpl delegateImpl);

    @Override // com.facebook.react.devsupport.M
    public native void closeQuietly();

    @Override // com.facebook.react.devsupport.M
    public native void connect();

    @Override // com.facebook.react.devsupport.M
    public native void sendEventToAllConnections(String str);
}
