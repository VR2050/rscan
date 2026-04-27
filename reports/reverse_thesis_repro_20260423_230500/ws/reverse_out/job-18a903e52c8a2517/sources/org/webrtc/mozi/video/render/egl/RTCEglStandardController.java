package org.webrtc.mozi.video.render.egl;

import android.os.Handler;
import android.os.HandlerThread;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.ThreadUtils;

/* JADX INFO: loaded from: classes3.dex */
public class RTCEglStandardController extends RTCEglControlAdapter {
    private static final String TAG = "EglStandardController";
    private HandlerThread mRenderThread;
    private Handler mRenderThreadHandler;

    public RTCEglStandardController(final EglBase.Context sharedContext, final int[] configAttributes) {
        RTCEglHandlerThread rTCEglHandlerThread = new RTCEglHandlerThread("McsEglRenderer");
        this.mRenderThread = rTCEglHandlerThread;
        rTCEglHandlerThread.start();
        Handler handler = new Handler(this.mRenderThread.getLooper());
        this.mRenderThreadHandler = handler;
        ThreadUtils.invokeAtFrontUninterruptibly(handler, new Runnable() { // from class: org.webrtc.mozi.video.render.egl.RTCEglStandardController.1
            @Override // java.lang.Runnable
            public void run() {
                if (sharedContext == null) {
                    Logging.d(RTCEglStandardController.TAG, "EglBase10.create context");
                    RTCEglStandardController.this.mEglBase = EglBase.createEgl10(configAttributes);
                } else {
                    Logging.d(RTCEglStandardController.TAG, "EglBase.create shared context");
                    RTCEglStandardController.this.mEglBase = EglBase.create(sharedContext, configAttributes);
                    RTCEglStandardController.this.mEglBase.setTraceId(RTCEglStandardController.TAG);
                }
            }
        });
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public void release() {
        if (this.mEglBase == null) {
            return;
        }
        final EglBase eglBase = this.mEglBase;
        this.mEglBase = null;
        this.mRenderThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.video.render.egl.RTCEglStandardController.2
            @Override // java.lang.Runnable
            public void run() {
                Logging.d(RTCEglStandardController.TAG, "release EglController");
                eglBase.detachCurrent();
                eglBase.release();
                RTCEglStandardController.this.mRenderThread.quit();
            }
        });
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglController
    public Handler getRenderHandler(final String name) {
        this.mRenderThreadHandler.post(new Runnable() { // from class: org.webrtc.mozi.video.render.egl.RTCEglStandardController.3
            @Override // java.lang.Runnable
            public void run() {
                try {
                    RTCEglStandardController.this.mRenderThread.setName(name);
                } catch (Throwable th) {
                    Logging.d(RTCEglStandardController.TAG, "set render thread name failed");
                }
            }
        });
        return this.mRenderThreadHandler;
    }

    @Override // org.webrtc.mozi.video.render.egl.RTCEglControlAdapter, org.webrtc.mozi.video.render.egl.RTCEglController
    public EglBase getEglBase() {
        return this.mEglBase;
    }
}
