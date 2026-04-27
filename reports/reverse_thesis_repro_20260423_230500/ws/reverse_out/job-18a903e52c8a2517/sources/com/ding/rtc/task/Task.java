package com.ding.rtc.task;

/* JADX INFO: loaded from: classes.dex */
public abstract class Task<T> extends SimpleTask {
    public abstract T doInBackground();

    public abstract void onFail(Throwable throwable);

    public abstract void onSuccess(T t);

    public Task() {
    }

    public Task(Priority priority) {
        super(priority);
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            final T t = doInBackground();
            TaskExecutor.getMainThreadHandler().post(new Runnable() { // from class: com.ding.rtc.task.Task.1
                /* JADX WARN: Multi-variable type inference failed */
                @Override // java.lang.Runnable
                public void run() {
                    Task.this.onSuccess(t);
                }
            });
        } catch (Throwable throwable) {
            TaskExecutor.getMainThreadHandler().post(new Runnable() { // from class: com.ding.rtc.task.Task.2
                @Override // java.lang.Runnable
                public void run() {
                    Task.this.onFail(throwable);
                }
            });
        }
    }
}
