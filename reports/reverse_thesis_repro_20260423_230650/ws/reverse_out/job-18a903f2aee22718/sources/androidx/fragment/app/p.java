package androidx.fragment.app;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.view.LayoutInflater;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* JADX INFO: loaded from: classes.dex */
public abstract class p extends AbstractC0300l {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Activity f5009b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Context f5010c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Handler f5011d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f5012e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final x f5013f;

    p(AbstractActivityC0298j abstractActivityC0298j) {
        this(abstractActivityC0298j, abstractActivityC0298j, new Handler(), 0);
    }

    Activity i() {
        return this.f5009b;
    }

    Context k() {
        return this.f5010c;
    }

    public Handler o() {
        return this.f5011d;
    }

    public abstract void v(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr);

    public abstract Object x();

    public abstract LayoutInflater y();

    public abstract void z();

    p(Activity activity, Context context, Handler handler, int i3) {
        this.f5013f = new y();
        this.f5009b = activity;
        this.f5010c = (Context) q.g.g(context, "context == null");
        this.f5011d = (Handler) q.g.g(handler, "handler == null");
        this.f5012e = i3;
    }
}
