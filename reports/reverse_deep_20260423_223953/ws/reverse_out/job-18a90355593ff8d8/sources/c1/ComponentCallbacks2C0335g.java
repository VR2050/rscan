package c1;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.res.Configuration;
import com.facebook.react.bridge.MemoryPressureListener;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* JADX INFO: renamed from: c1.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class ComponentCallbacks2C0335g implements ComponentCallbacks2 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final CopyOnWriteArrayList f5567b = new CopyOnWriteArrayList();

    public ComponentCallbacks2C0335g(Context context) {
        context.getApplicationContext().registerComponentCallbacks(this);
    }

    private void c(int i3) {
        Iterator it = this.f5567b.iterator();
        while (it.hasNext()) {
            ((MemoryPressureListener) it.next()).handleMemoryPressure(i3);
        }
    }

    public void a(MemoryPressureListener memoryPressureListener) {
        if (this.f5567b.contains(memoryPressureListener)) {
            return;
        }
        this.f5567b.add(memoryPressureListener);
    }

    public void b(Context context) {
        context.getApplicationContext().unregisterComponentCallbacks(this);
    }

    public void d(MemoryPressureListener memoryPressureListener) {
        this.f5567b.remove(memoryPressureListener);
    }

    @Override // android.content.ComponentCallbacks2
    public void onTrimMemory(int i3) {
        c(i3);
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
    }
}
