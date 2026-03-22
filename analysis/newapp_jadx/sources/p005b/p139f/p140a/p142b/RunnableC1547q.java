package p005b.p139f.p140a.p142b;

import android.app.Activity;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/* renamed from: b.f.a.b.q */
/* loaded from: classes.dex */
public class RunnableC1547q implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ Activity f1789c;

    /* renamed from: e */
    public final /* synthetic */ C1545o f1790e;

    /* renamed from: f */
    public final /* synthetic */ C1549s f1791f;

    public RunnableC1547q(C1549s c1549s, Activity activity, C1545o c1545o) {
        this.f1791f = c1549s;
        this.f1789c = activity;
        this.f1790e = c1545o;
    }

    @Override // java.lang.Runnable
    public void run() {
        C1549s c1549s = this.f1791f;
        Activity activity = this.f1789c;
        C1545o c1545o = this.f1790e;
        List<C1545o> list = c1549s.f1799h.get(activity);
        if (list == null) {
            list = new CopyOnWriteArrayList<>();
            c1549s.f1799h.put(activity, list);
        } else if (list.contains(c1545o)) {
            return;
        }
        list.add(c1545o);
    }
}
