package com.facebook.react.bridge.queue;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class MessageQueueThreadHandler extends Handler {
    private final QueueThreadExceptionHandler exceptionHandler;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MessageQueueThreadHandler(Looper looper, QueueThreadExceptionHandler queueThreadExceptionHandler) {
        super(looper);
        j.f(looper, "looper");
        j.f(queueThreadExceptionHandler, "exceptionHandler");
        this.exceptionHandler = queueThreadExceptionHandler;
    }

    @Override // android.os.Handler
    public void dispatchMessage(Message message) {
        j.f(message, "msg");
        try {
            super.dispatchMessage(message);
        } catch (Exception e3) {
            this.exceptionHandler.handleException(e3);
        }
    }
}
