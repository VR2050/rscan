package k1;

import androidx.activity.result.d;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UIManagerListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import l1.InterfaceC0621a;
import l1.b;
import t2.j;

/* JADX INFO: renamed from: k1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0604a implements UIManagerListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final List f9420b = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f9421c = new ArrayList();

    public final synchronized void a(InterfaceC0621a interfaceC0621a) {
        j.f(interfaceC0621a, "block");
        this.f9421c.add(interfaceC0621a);
    }

    public final synchronized void b(InterfaceC0621a interfaceC0621a) {
        j.f(interfaceC0621a, "block");
        this.f9420b.add(interfaceC0621a);
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didDispatchMountItems(UIManager uIManager) {
        j.f(uIManager, "uiManager");
        didMountItems(uIManager);
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didMountItems(UIManager uIManager) {
        j.f(uIManager, "uiManager");
        if (this.f9421c.isEmpty()) {
            return;
        }
        Iterator it = this.f9421c.iterator();
        while (it.hasNext()) {
            d.a(it.next());
            if (uIManager instanceof b) {
                throw null;
            }
        }
        this.f9421c.clear();
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didScheduleMountItems(UIManager uIManager) {
        j.f(uIManager, "uiManager");
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void willDispatchViewUpdates(UIManager uIManager) {
        j.f(uIManager, "uiManager");
        willMountItems(uIManager);
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void willMountItems(UIManager uIManager) {
        j.f(uIManager, "uiManager");
        if (this.f9420b.isEmpty()) {
            return;
        }
        Iterator it = this.f9420b.iterator();
        while (it.hasNext()) {
            d.a(it.next());
            if (uIManager instanceof b) {
                throw null;
            }
        }
        this.f9420b.clear();
    }
}
