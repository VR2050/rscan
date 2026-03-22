package p005b.p187j.p188a;

import android.view.View;
import com.flyco.tablayout.CommonTabLayout;
import p005b.p187j.p188a.p189d.InterfaceC1879b;

/* renamed from: b.j.a.a */
/* loaded from: classes.dex */
public class ViewOnClickListenerC1875a implements View.OnClickListener {

    /* renamed from: c */
    public final /* synthetic */ CommonTabLayout f2893c;

    public ViewOnClickListenerC1875a(CommonTabLayout commonTabLayout) {
        this.f2893c = commonTabLayout;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int intValue = ((Integer) view.getTag()).intValue();
        CommonTabLayout commonTabLayout = this.f2893c;
        if (commonTabLayout.f9062g == intValue) {
            InterfaceC1879b interfaceC1879b = commonTabLayout.f9057c0;
            if (interfaceC1879b != null) {
                interfaceC1879b.m1211a(intValue);
                return;
            }
            return;
        }
        commonTabLayout.setCurrentTab(intValue);
        InterfaceC1879b interfaceC1879b2 = this.f2893c.f9057c0;
        if (interfaceC1879b2 != null) {
            interfaceC1879b2.m1212b(intValue);
        }
    }
}
