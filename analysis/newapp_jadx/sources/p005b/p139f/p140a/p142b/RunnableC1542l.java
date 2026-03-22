package p005b.p139f.p140a.p142b;

import com.blankj.utilcode.util.ToastUtils;
import java.lang.ref.WeakReference;

/* renamed from: b.f.a.b.l */
/* loaded from: classes.dex */
public class RunnableC1542l implements Runnable {
    @Override // java.lang.Runnable
    public void run() {
        WeakReference<ToastUtils.InterfaceC3217c> weakReference = ToastUtils.f8826b;
        if (weakReference != null) {
            ToastUtils.InterfaceC3217c interfaceC3217c = weakReference.get();
            if (interfaceC3217c != null) {
                interfaceC3217c.cancel();
            }
            ToastUtils.f8826b = null;
        }
    }
}
