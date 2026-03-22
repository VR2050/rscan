package p005b.p006a.p007a.p008a.p016q;

import com.jbzd.media.movecartoons.bean.response.UploadBean;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4928c;
import p476m.p496b.p500b.p501f.InterfaceC4933c;
import p476m.p496b.p500b.p502g.InterfaceC4938a;
import p476m.p496b.p500b.p503h.C4945d;
import p476m.p496b.p500b.p503h.C4946e;

/* renamed from: b.a.a.a.q.f */
/* loaded from: classes2.dex */
public final class C0916f {
    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: a */
    public static final void m218a(@NotNull UploadBean bean) {
        Intrinsics.checkNotNullParameter(bean, "bean");
        C0914d c0914d = C0911a.f369a;
        if (c0914d == 0) {
            Intrinsics.throwUninitializedPropertyAccessException("mDaoSession");
            throw null;
        }
        AbstractC4926a<?, ?> m5603a = c0914d.m5603a(bean.getClass());
        m5603a.m5598a();
        Object mo4196c = m5603a.mo4196c(bean);
        if (mo4196c == 0) {
            throw new C4928c("Entity has no key");
        }
        m5603a.m5598a();
        C4946e c4946e = m5603a.f12576e;
        if (c4946e.f12620d == null) {
            String str = c4946e.f12618b;
            String[] strArr = c4946e.f12619c;
            int i2 = C4945d.f12616a;
            String str2 = Typography.quote + str + Typography.quote;
            StringBuilder sb = new StringBuilder("DELETE FROM ");
            sb.append(str2);
            if (strArr != null && strArr.length > 0) {
                sb.append(" WHERE ");
                for (int i3 = 0; i3 < strArr.length; i3++) {
                    String str3 = strArr[i3];
                    sb.append(str2);
                    sb.append(".\"");
                    sb.append(str3);
                    sb.append(Typography.quote);
                    sb.append("=?");
                    if (i3 < strArr.length - 1) {
                        sb.append(',');
                    }
                }
            }
            InterfaceC4933c compileStatement = c4946e.f12617a.compileStatement(sb.toString());
            synchronized (c4946e) {
                if (c4946e.f12620d == null) {
                    c4946e.f12620d = compileStatement;
                }
            }
            if (c4946e.f12620d != compileStatement) {
                compileStatement.close();
            }
        }
        InterfaceC4933c interfaceC4933c = c4946e.f12620d;
        if (m5603a.f12573b.isDbLockedByCurrentThread()) {
            synchronized (interfaceC4933c) {
                m5603a.m5599b(mo4196c, interfaceC4933c);
            }
        } else {
            m5603a.f12573b.beginTransaction();
            try {
                synchronized (interfaceC4933c) {
                    m5603a.m5599b(mo4196c, interfaceC4933c);
                }
                m5603a.f12573b.setTransactionSuccessful();
            } finally {
                m5603a.f12573b.endTransaction();
            }
        }
        InterfaceC4938a<?, ?> interfaceC4938a = m5603a.f12574c;
        if (interfaceC4938a != null) {
            interfaceC4938a.remove(mo4196c);
        }
    }
}
