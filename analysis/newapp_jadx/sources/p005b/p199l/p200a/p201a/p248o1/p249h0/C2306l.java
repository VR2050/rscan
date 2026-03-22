package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.WorkerThread;
import java.util.Iterator;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;

/* renamed from: b.l.a.a.o1.h0.l */
/* loaded from: classes.dex */
public final class C2306l {

    /* renamed from: a */
    public static final /* synthetic */ int f5869a = 0;

    @WorkerThread
    /* renamed from: a */
    public static void m2226a(InterfaceC2297c interfaceC2297c, String str) {
        Iterator<C2305k> it = interfaceC2297c.mo2211l(str).iterator();
        while (it.hasNext()) {
            try {
                interfaceC2297c.mo2203d(it.next());
            } catch (InterfaceC2297c.a unused) {
            }
        }
    }
}
