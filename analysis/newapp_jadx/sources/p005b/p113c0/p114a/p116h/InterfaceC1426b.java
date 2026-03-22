package p005b.p113c0.p114a.p116h;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import com.yalantis.ucrop.view.CropImageView;
import java.util.List;
import p005b.p113c0.p114a.p115g.C1415a;
import p005b.p113c0.p114a.p115g.C1419e;
import p005b.p113c0.p114a.p116h.p117g.C1432b;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.EnumC1456b;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p130l.C1495g;

/* renamed from: b.c0.a.h.b */
/* loaded from: classes2.dex */
public interface InterfaceC1426b {

    /* renamed from: a */
    public static final InterfaceC1426b f1376a = new a();

    /* renamed from: b.c0.a.h.b$a */
    public static class a implements InterfaceC1426b {
        @Override // p005b.p113c0.p114a.p116h.InterfaceC1426b
        /* renamed from: a */
        public void mo491a(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d, @NonNull Throwable th) {
            if (th instanceof C1415a) {
                ((C1466l) interfaceC1458d).f1437b.mo5529i(((C1415a) th).f1373c);
            } else {
                ((C1466l) interfaceC1458d).f1437b.mo5529i(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION);
            }
            ((C1466l) interfaceC1458d).f1437b.mo5527d(new C1466l.b(new C1432b(th.getMessage(), C1495g.f1510k), null));
        }
    }

    /* renamed from: b.c0.a.h.b$b */
    public static class b implements InterfaceC1426b {
        public b(InterfaceC1426b interfaceC1426b) {
        }

        @Override // p005b.p113c0.p114a.p116h.InterfaceC1426b
        /* renamed from: a */
        public void mo491a(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d, @NonNull Throwable th) {
            List<EnumC1456b> list;
            if ((th instanceof C1419e) && (list = ((C1419e) th).f1375e) != null && list.size() > 0) {
                ((C1466l) interfaceC1458d).f1437b.mo5520o("Allow", TextUtils.join(", ", list));
            }
            ((a) InterfaceC1426b.f1376a).mo491a(interfaceC1457c, interfaceC1458d, th);
        }
    }

    /* renamed from: a */
    void mo491a(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d, @NonNull Throwable th);
}
