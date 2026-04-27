package com.ding.rtc.task;

/* JADX INFO: loaded from: classes.dex */
public abstract class SimpleTask implements Runnable {
    long SEQ;
    public Priority priority;
    public String taskName;

    public SimpleTask() {
        this.priority = Priority.NORMAL;
    }

    public SimpleTask(Priority priority) {
        this.priority = priority == null ? Priority.NORMAL : priority;
    }
}
