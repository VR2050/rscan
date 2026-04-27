package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public interface RefCounted {
    boolean isReleased();

    void release();

    void retain();
}
