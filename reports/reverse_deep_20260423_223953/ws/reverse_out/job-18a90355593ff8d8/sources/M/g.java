package M;

import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private WebSettingsBoundaryInterface f1752a;

    public g(WebSettingsBoundaryInterface webSettingsBoundaryInterface) {
        this.f1752a = webSettingsBoundaryInterface;
    }

    public void a(int i3) {
        this.f1752a.setForceDark(i3);
    }

    public void b(int i3) {
        this.f1752a.setForceDarkBehavior(i3);
    }
}
