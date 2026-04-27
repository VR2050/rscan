package com.ding.rtc.http;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* JADX INFO: loaded from: classes.dex */
public class HttpAsyncNativeResponse implements HttpAsyncResponse {
    private long mNativeHandle;
    private final ReadWriteLock mNativeHandleLock = new ReentrantReadWriteLock();

    private native void onHttpResult(long nativeHandle, HttpStackResponse response);

    private HttpAsyncNativeResponse(long nativeHandle) {
        this.mNativeHandle = 0L;
        this.mNativeHandle = nativeHandle;
    }

    @Override // com.ding.rtc.http.HttpAsyncResponse
    public void onHttpResult(HttpStackResponse response) {
        this.mNativeHandleLock.readLock().lock();
        onHttpResult(this.mNativeHandle, response);
        this.mNativeHandleLock.readLock().unlock();
    }

    private void setNativeHandle(long nativeHandle) {
        this.mNativeHandleLock.writeLock().lock();
        this.mNativeHandle = nativeHandle;
        this.mNativeHandleLock.writeLock().unlock();
    }
}
