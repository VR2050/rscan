package p005b.p187j.p188a;

import android.view.View;
import com.flyco.tablayout.SegmentTabLayout;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* renamed from: b.j.a.b */
/* loaded from: classes.dex */
public class ViewOnClickListenerC1876b implements View.OnClickListener {

    /* renamed from: c */
    public final /* synthetic */ SegmentTabLayout f2894c;

    public ViewOnClickListenerC1876b(SegmentTabLayout segmentTabLayout) {
        this.f2894c = segmentTabLayout;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int intValue = ((Integer) view.getTag()).intValue();
        SegmentTabLayout segmentTabLayout = this.f2894c;
        if (segmentTabLayout.f9108g == intValue) {
            InterfaceC1879b interfaceC1879b = segmentTabLayout.f9102P;
            if (interfaceC1879b != null) {
                interfaceC1879b.m1211a(intValue);
                return;
            }
            return;
        }
        segmentTabLayout.setCurrentTab(intValue);
        InterfaceC1879b interfaceC1879b2 = this.f2894c.f9102P;
        if (interfaceC1879b2 != null) {
            interfaceC1879b2.m1212b(intValue);
        }
    }
}
