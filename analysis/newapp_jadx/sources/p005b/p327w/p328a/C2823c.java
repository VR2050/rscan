package p005b.p327w.p328a;

import android.text.TextUtils;
import java.io.File;
import java.util.Objects;
import p005b.p113c0.p114a.p115g.C1422h;
import p005b.p113c0.p114a.p115g.C1423i;
import p005b.p113c0.p114a.p116h.InterfaceC1429e;
import p005b.p113c0.p114a.p116h.p117g.C1431a;
import p005b.p113c0.p114a.p116h.p120j.AbstractC1439c;
import p005b.p113c0.p114a.p116h.p121k.C1443a;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p122l.C1448b;
import p005b.p113c0.p114a.p116h.p122l.InterfaceC1449c;
import p005b.p113c0.p114a.p124i.EnumC1456b;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.p126o.InterfaceC1473c;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.w.a.c */
/* loaded from: classes2.dex */
public final class C2823c extends AbstractC1439c {

    /* renamed from: g */
    public Object f7667g;

    public C2823c(Object obj, C1444b c1444b, C1443a c1443a) {
        super(obj, c1444b, c1443a);
        this.f7667g = obj;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.AbstractC1439c
    /* renamed from: b */
    public InterfaceC1449c mo504b(InterfaceC1457c interfaceC1457c, InterfaceC1458d interfaceC1458d) {
        C1423i c1423i;
        String path = interfaceC1457c.getPath();
        EnumC1456b mo523d = interfaceC1457c.mo523d();
        Object mo518a = interfaceC1457c.mo518a("http.message.converter");
        if (mo518a != null && (mo518a instanceof InterfaceC1429e)) {
        }
        if (interfaceC1457c instanceof InterfaceC1473c) {
        }
        if (mo523d.m521a()) {
            interfaceC1457c.mo526h();
        }
        m503a(path);
        String mo527i = interfaceC1457c.mo527i("taskId");
        if (TextUtils.isEmpty(mo527i)) {
            throw new C1422h("taskId");
        }
        try {
            String valueOf = String.valueOf(mo527i);
            String mo527i2 = interfaceC1457c.mo527i("fileName");
            if (TextUtils.isEmpty(mo527i2)) {
                throw new C1422h("fileName");
            }
            try {
                String valueOf2 = String.valueOf(mo527i2);
                Objects.requireNonNull((C2821a) this.f7667g);
                StringBuilder sb = new StringBuilder();
                C1499a.m608b0(sb, C2821a.f7664a, "/", valueOf, "/");
                sb.append(valueOf2);
                return new C1448b(true, new C1431a(new File(sb.toString())));
            } finally {
            }
        } finally {
        }
    }
}
