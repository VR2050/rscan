package p005b.p006a.p007a.p008a.p016q;

import com.jbzd.media.movecartoons.bean.response.UploadBean;
import com.jbzd.media.movecartoons.greendao.UploadBeanDao;
import java.util.Map;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4927b;
import p476m.p496b.p500b.p501f.InterfaceC4931a;
import p476m.p496b.p500b.p502g.C4939b;
import p476m.p496b.p500b.p502g.C4940c;
import p476m.p496b.p500b.p502g.EnumC4941d;
import p476m.p496b.p500b.p503h.C4942a;

/* renamed from: b.a.a.a.q.d */
/* loaded from: classes2.dex */
public class C0914d extends C4927b {

    /* renamed from: b */
    public final C4942a f370b;

    /* renamed from: c */
    public final UploadBeanDao f371c;

    public C0914d(InterfaceC4931a interfaceC4931a, EnumC4941d enumC4941d, Map<Class<? extends AbstractC4926a<?, ?>>, C4942a> map) {
        super(interfaceC4931a);
        C4942a c4942a = new C4942a(map.get(UploadBeanDao.class));
        this.f370b = c4942a;
        if (enumC4941d == EnumC4941d.None) {
            c4942a.f12605m = null;
        } else {
            if (enumC4941d != EnumC4941d.Session) {
                throw new IllegalArgumentException("Unsupported type: " + enumC4941d);
            }
            if (c4942a.f12603k) {
                c4942a.f12605m = new C4939b();
            } else {
                c4942a.f12605m = new C4940c();
            }
        }
        UploadBeanDao uploadBeanDao = new UploadBeanDao(c4942a, this);
        this.f371c = uploadBeanDao;
        this.f12578a.put(UploadBean.class, uploadBeanDao);
    }
}
