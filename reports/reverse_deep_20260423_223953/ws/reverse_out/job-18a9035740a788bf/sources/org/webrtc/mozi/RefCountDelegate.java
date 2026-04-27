package org.webrtc.mozi;

import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes3.dex */
class RefCountDelegate implements RefCounted {
    private final AtomicInteger refCount = new AtomicInteger(1);

    @Nullable
    private final Runnable releaseCallback;

    public RefCountDelegate(@Nullable Runnable releaseCallback) {
        this.releaseCallback = releaseCallback;
    }

    @Override // org.webrtc.mozi.RefCounted
    public void retain() {
        this.refCount.incrementAndGet();
    }

    @Override // org.webrtc.mozi.RefCounted
    public void release() {
        Runnable runnable;
        if (this.refCount.decrementAndGet() == 0 && (runnable = this.releaseCallback) != null) {
            runnable.run();
        }
    }

    @Override // org.webrtc.mozi.RefCounted
    public boolean isReleased() {
        return this.refCount.get() <= 0;
    }
}
