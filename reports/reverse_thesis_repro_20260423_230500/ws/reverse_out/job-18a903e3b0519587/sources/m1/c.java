package m1;

import android.os.SystemClock;
import c2.C0353a;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.RetryableMountingLayerException;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.fabric.FabricUIManager;
import com.facebook.react.fabric.mounting.mountitems.MountItem;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import q1.C0655b;

/* JADX INFO: loaded from: classes.dex */
public class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d f9610a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final a f9611b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ConcurrentLinkedQueue f9612c = new ConcurrentLinkedQueue();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ConcurrentLinkedQueue f9613d = new ConcurrentLinkedQueue();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ConcurrentLinkedQueue f9614e = new ConcurrentLinkedQueue();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f9615f = false;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private long f9616g = 0;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private long f9617h = 0;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private long f9618i = 0;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f9619j = false;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Runnable f9620k = new Runnable() { // from class: m1.b
        @Override // java.lang.Runnable
        public final void run() {
            this.f9609b.p();
        }
    };

    public interface a {
        void a(List list);

        void b(List list);

        void c();
    }

    public c(d dVar, a aVar) {
        this.f9610a = dVar;
        this.f9611b = aVar;
    }

    private void e() {
        boolean zIsIgnorable;
        this.f9616g = 0L;
        this.f9617h = SystemClock.uptimeMillis();
        List<com.facebook.react.fabric.mounting.mountitems.c> listM = m();
        List<MountItem> listK = k();
        if (listK == null && listM == null) {
            return;
        }
        this.f9611b.b(listK);
        if (listM != null) {
            C0353a.c(0L, "MountItemDispatcher::mountViews viewCommandMountItems");
            for (com.facebook.react.fabric.mounting.mountitems.c cVar : listM) {
                if (C0655b.e()) {
                    q(cVar, "dispatchMountItems: Executing viewCommandMountItem");
                }
                try {
                    j(cVar);
                } catch (RetryableMountingLayerException e3) {
                    if (cVar.b() == 0) {
                        cVar.c();
                        d(cVar);
                    } else {
                        ReactSoftExceptionLogger.logSoftException("MountItemDispatcher", new ReactNoCrashSoftException("Caught exception executing ViewCommand: " + cVar.toString(), e3));
                    }
                } catch (Throwable th) {
                    ReactSoftExceptionLogger.logSoftException("MountItemDispatcher", new RuntimeException("Caught exception executing ViewCommand: " + cVar.toString(), th));
                }
            }
            C0353a.i(0L);
        }
        List<MountItem> listL = l();
        if (listL != null) {
            C0353a.c(0L, "MountItemDispatcher::mountViews preMountItems");
            for (MountItem mountItem : listL) {
                if (C0655b.e()) {
                    q(mountItem, "dispatchMountItems: Executing preMountItem");
                }
                j(mountItem);
            }
            C0353a.i(0L);
        }
        if (listK != null) {
            C0353a.c(0L, "MountItemDispatcher::mountViews mountItems to execute");
            long jUptimeMillis = SystemClock.uptimeMillis();
            for (MountItem mountItem2 : listK) {
                if (C0655b.e()) {
                    q(mountItem2, "dispatchMountItems: Executing mountItem");
                }
                try {
                    j(mountItem2);
                } finally {
                    if (zIsIgnorable) {
                    }
                }
            }
            this.f9616g += SystemClock.uptimeMillis() - jUptimeMillis;
            C0353a.i(0L);
        }
        this.f9611b.a(listK);
    }

    /* JADX WARN: Finally extract failed */
    private void h(long j3) {
        MountItem mountItem;
        C0353a.c(0L, "MountItemDispatcher::premountViews");
        this.f9615f = true;
        while (System.nanoTime() <= j3 && (mountItem = (MountItem) this.f9614e.poll()) != null) {
            try {
                if (C0655b.e()) {
                    q(mountItem, "dispatchPreMountItems");
                }
                j(mountItem);
            } catch (Throwable th) {
                this.f9615f = false;
                throw th;
            }
        }
        this.f9615f = false;
        C0353a.i(0L);
    }

    private static List i(ConcurrentLinkedQueue concurrentLinkedQueue) {
        if (concurrentLinkedQueue.isEmpty()) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        do {
            Object objPoll = concurrentLinkedQueue.poll();
            if (objPoll != null) {
                arrayList.add(objPoll);
            }
        } while (!concurrentLinkedQueue.isEmpty());
        if (arrayList.size() == 0) {
            return null;
        }
        return arrayList;
    }

    private void j(MountItem mountItem) {
        if (!this.f9610a.l(mountItem.getSurfaceId())) {
            mountItem.execute(this.f9610a);
            return;
        }
        if (C0655b.e()) {
            Y.a.o("MountItemDispatcher", "executeOrEnqueue: Item execution delayed, surface %s is not ready yet", Integer.valueOf(mountItem.getSurfaceId()));
        }
        this.f9610a.f(mountItem.getSurfaceId()).F(mountItem);
    }

    private List k() {
        return i(this.f9613d);
    }

    private List l() {
        return i(this.f9614e);
    }

    private List m() {
        return i(this.f9612c);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void p() {
        this.f9619j = false;
        if (this.f9614e.isEmpty()) {
            return;
        }
        h(this.f9618i + 8333333);
    }

    private static void q(MountItem mountItem, String str) {
        for (String str2 : mountItem.toString().split("\n")) {
            Y.a.m("MountItemDispatcher", str + ": " + str2);
        }
    }

    public void b(MountItem mountItem) {
        this.f9613d.add(mountItem);
    }

    public void c(MountItem mountItem) {
        if (!this.f9610a.t(mountItem.getSurfaceId())) {
            this.f9614e.add(mountItem);
        } else if (FabricUIManager.IS_DEVELOPMENT_ENVIRONMENT) {
            Y.a.o("MountItemDispatcher", "Not queueing PreAllocateMountItem: surfaceId stopped: [%d] - %s", Integer.valueOf(mountItem.getSurfaceId()), mountItem.toString());
        }
    }

    public void d(com.facebook.react.fabric.mounting.mountitems.c cVar) {
        this.f9612c.add(cVar);
    }

    public void f(Queue queue) {
        while (!queue.isEmpty()) {
            MountItem mountItem = (MountItem) queue.poll();
            try {
                mountItem.execute(this.f9610a);
            } catch (RetryableMountingLayerException e3) {
                if (mountItem instanceof com.facebook.react.fabric.mounting.mountitems.c) {
                    com.facebook.react.fabric.mounting.mountitems.c cVar = (com.facebook.react.fabric.mounting.mountitems.c) mountItem;
                    if (cVar.b() == 0) {
                        cVar.c();
                        d(cVar);
                    }
                } else {
                    q(mountItem, "dispatchExternalMountItems: mounting failed with " + e3.getMessage());
                }
            }
        }
    }

    public void g(long j3) {
        this.f9618i = j3;
        if (this.f9614e.isEmpty()) {
            return;
        }
        if (!C0655b.i()) {
            h(this.f9618i + 8333333);
        } else {
            if (this.f9619j) {
                return;
            }
            this.f9619j = true;
            UiThreadUtil.getUiThreadHandler().post(this.f9620k);
        }
    }

    public long n() {
        return this.f9616g;
    }

    public long o() {
        return this.f9617h;
    }

    public void r() {
        if (this.f9615f) {
            return;
        }
        this.f9615f = true;
        try {
            e();
            this.f9615f = false;
            this.f9611b.c();
        } catch (Throwable th) {
            this.f9615f = false;
            throw th;
        }
    }
}
