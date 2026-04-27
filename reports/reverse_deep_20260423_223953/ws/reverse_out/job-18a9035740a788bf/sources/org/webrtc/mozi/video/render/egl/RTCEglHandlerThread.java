package org.webrtc.mozi.video.render.egl;

import android.os.HandlerThread;
import java.util.concurrent.atomic.AtomicInteger;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class RTCEglHandlerThread extends HandlerThread {
    private static final String TAG = "McsHandlerThread";
    private static AtomicInteger sThreadCount = new AtomicInteger();

    public RTCEglHandlerThread(String name) {
        super(name);
    }

    public RTCEglHandlerThread(String name, int priority) {
        super(name, priority);
    }

    @Override // java.lang.Thread
    public synchronized void start() {
        super.start();
        Logging.d(TAG, "McsHandlerThread(" + getName() + ") start, total count: " + sThreadCount.incrementAndGet());
    }

    @Override // android.os.HandlerThread
    public boolean quit() {
        onQuit();
        return super.quit();
    }

    @Override // android.os.HandlerThread
    public boolean quitSafely() {
        onQuit();
        return super.quitSafely();
    }

    private void onQuit() {
        Logging.d(TAG, "McsHandlerThread(" + getName() + ") quit, total count: " + sThreadCount.decrementAndGet());
    }
}
