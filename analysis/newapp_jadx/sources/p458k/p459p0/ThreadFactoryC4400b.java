package p458k.p459p0;

import java.util.concurrent.ThreadFactory;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.b */
/* loaded from: classes3.dex */
public final class ThreadFactoryC4400b implements ThreadFactory {

    /* renamed from: c */
    public final /* synthetic */ String f11554c;

    /* renamed from: e */
    public final /* synthetic */ boolean f11555e;

    public ThreadFactoryC4400b(String str, boolean z) {
        this.f11554c = str;
        this.f11555e = z;
    }

    @Override // java.util.concurrent.ThreadFactory
    @NotNull
    public final Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, this.f11554c);
        thread.setDaemon(this.f11555e);
        return thread;
    }
}
