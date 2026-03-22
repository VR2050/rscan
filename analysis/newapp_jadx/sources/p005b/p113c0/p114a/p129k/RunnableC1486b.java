package p005b.p113c0.p114a.p129k;

import com.qunidayede.service.CoreService;
import com.qunidayede.service.ServerManager;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import p005b.p113c0.p114a.InterfaceC1414f;
import p005b.p113c0.p114a.p130l.C1490b;
import p476m.p477a.p485b.p488j0.p489h.C4820a;

/* renamed from: b.c0.a.k.b */
/* loaded from: classes2.dex */
public class RunnableC1486b implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ AbstractC1487c f1481c;

    /* renamed from: b.c0.a.k.b$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            InterfaceC1414f.a aVar = RunnableC1486b.this.f1481c.f1485c;
            if (aVar != null) {
                ServerManager.m4566a(CoreService.this, 4, null);
            }
        }
    }

    public RunnableC1486b(AbstractC1487c abstractC1487c) {
        this.f1481c = abstractC1487c;
    }

    @Override // java.lang.Runnable
    public void run() {
        C4820a c4820a = this.f1481c.f1486d;
        if (c4820a != null) {
            c4820a.m5488a(3L, TimeUnit.SECONDS);
            this.f1481c.f1487e = false;
            C1490b m560a = C1490b.m560a();
            a aVar = new a();
            Objects.requireNonNull(m560a);
            C1490b.f1497b.post(aVar);
        }
    }
}
