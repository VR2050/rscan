package com.jeffmony.m3u8library.listener;

/* loaded from: classes2.dex */
public interface IVideoTransformListener {
    void onTransformFailed(Exception exc);

    void onTransformFinished();

    void onTransformProgress(float f2);
}
