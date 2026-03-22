package p005b.p139f.p140a.p142b;

import android.app.Activity;
import java.util.List;

/* renamed from: b.f.a.b.r */
/* loaded from: classes.dex */
public class RunnableC1548r implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ Activity f1792c;

    /* renamed from: e */
    public final /* synthetic */ C1545o f1793e;

    /* renamed from: f */
    public final /* synthetic */ C1549s f1794f;

    public RunnableC1548r(C1549s c1549s, Activity activity, C1545o c1545o) {
        this.f1794f = c1549s;
        this.f1792c = activity;
        this.f1793e = c1545o;
    }

    @Override // java.lang.Runnable
    public void run() {
        C1549s c1549s = this.f1794f;
        Activity activity = this.f1792c;
        C1545o c1545o = this.f1793e;
        List<C1545o> list = c1549s.f1799h.get(activity);
        if (list == null || list.isEmpty()) {
            return;
        }
        list.remove(c1545o);
    }
}
