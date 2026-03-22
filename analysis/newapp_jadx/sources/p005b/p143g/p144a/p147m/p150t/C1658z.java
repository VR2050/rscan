package p005b.p143g.p144a.p147m.p150t;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;

/* renamed from: b.g.a.m.t.z */
/* loaded from: classes.dex */
public class C1658z {

    /* renamed from: a */
    public boolean f2337a;

    /* renamed from: b */
    public final Handler f2338b = new Handler(Looper.getMainLooper(), new a());

    /* renamed from: b.g.a.m.t.z$a */
    public static final class a implements Handler.Callback {
        @Override // android.os.Handler.Callback
        public boolean handleMessage(Message message) {
            if (message.what != 1) {
                return false;
            }
            ((InterfaceC1655w) message.obj).recycle();
            return true;
        }
    }

    /* renamed from: a */
    public synchronized void m959a(InterfaceC1655w<?> interfaceC1655w, boolean z) {
        if (!this.f2337a && !z) {
            this.f2337a = true;
            interfaceC1655w.recycle();
            this.f2337a = false;
        }
        this.f2338b.obtainMessage(1, interfaceC1655w).sendToTarget();
    }
}
