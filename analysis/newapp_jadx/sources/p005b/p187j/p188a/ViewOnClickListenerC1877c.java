package p005b.p187j.p188a;

import android.view.View;
import com.flyco.tablayout.SlidingTabLayout;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* renamed from: b.j.a.c */
/* loaded from: classes.dex */
public class ViewOnClickListenerC1877c implements View.OnClickListener {

    /* renamed from: c */
    public final /* synthetic */ SlidingTabLayout f2895c;

    public ViewOnClickListenerC1877c(SlidingTabLayout slidingTabLayout) {
        this.f2895c = slidingTabLayout;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int indexOfChild = this.f2895c.f9160g.indexOfChild(view);
        if (indexOfChild != -1) {
            if (this.f2895c.f9158e.getCurrentItem() == indexOfChild) {
                InterfaceC1879b interfaceC1879b = this.f2895c.f9155b0;
                if (interfaceC1879b != null) {
                    interfaceC1879b.m1211a(indexOfChild);
                    return;
                }
                return;
            }
            SlidingTabLayout slidingTabLayout = this.f2895c;
            if (slidingTabLayout.f9152V) {
                slidingTabLayout.f9158e.setCurrentItem(indexOfChild, false);
            } else {
                slidingTabLayout.f9158e.setCurrentItem(indexOfChild);
            }
            InterfaceC1879b interfaceC1879b2 = this.f2895c.f9155b0;
            if (interfaceC1879b2 != null) {
                interfaceC1879b2.m1212b(indexOfChild);
            }
        }
    }
}
