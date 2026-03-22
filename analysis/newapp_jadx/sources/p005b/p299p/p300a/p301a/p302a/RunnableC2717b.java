package p005b.p299p.p300a.p301a.p302a;

import android.view.animation.LinearInterpolator;
import android.widget.Scroller;

/* renamed from: b.p.a.a.a.b */
/* loaded from: classes2.dex */
public class RunnableC2717b implements Runnable {

    /* renamed from: c */
    public Scroller f7385c;

    /* renamed from: e */
    public InterfaceC2716a f7386e;

    /* renamed from: f */
    public int f7387f;

    /* renamed from: g */
    public int f7388g;

    public RunnableC2717b(InterfaceC2716a interfaceC2716a) {
        this.f7386e = interfaceC2716a;
        this.f7385c = new Scroller(interfaceC2716a.getContext(), new LinearInterpolator());
    }

    @Override // java.lang.Runnable
    public void run() {
        if (!this.f7385c.computeScrollOffset()) {
            this.f7386e.removeCallbacks(this);
            this.f7386e.mo3237a();
            return;
        }
        int currX = this.f7385c.getCurrX();
        int currY = this.f7385c.getCurrY();
        this.f7386e.mo3238b(this.f7387f, this.f7388g, currX, currY);
        this.f7386e.post(this);
        this.f7387f = currX;
        this.f7388g = currY;
    }
}
