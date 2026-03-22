package p005b.p139f.p140a.p142b;

import android.app.Activity;
import androidx.annotation.NonNull;
import com.blankj.utilcode.util.ToastUtils;

/* renamed from: b.f.a.b.n */
/* loaded from: classes.dex */
public class C1544n extends C1545o {

    /* renamed from: a */
    public final /* synthetic */ int f1787a;

    /* renamed from: b */
    public final /* synthetic */ ToastUtils.C3216b f1788b;

    public C1544n(ToastUtils.C3216b c3216b, int i2) {
        this.f1788b = c3216b;
        this.f1787a = i2;
    }

    @Override // p005b.p139f.p140a.p142b.C1545o
    /* renamed from: a */
    public void mo715a(@NonNull Activity activity) {
        ToastUtils.C3216b c3216b = this.f1788b;
        if (c3216b.f8833e != null) {
            c3216b.m3889f(activity, this.f1787a, false);
        }
    }
}
