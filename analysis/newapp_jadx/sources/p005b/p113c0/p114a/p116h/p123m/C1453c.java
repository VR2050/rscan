package p005b.p113c0.p114a.p116h.p123m;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.File;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import p005b.p113c0.p114a.p115g.C1421g;
import p005b.p113c0.p114a.p116h.p117g.C1431a;
import p005b.p113c0.p114a.p116h.p117g.C1432b;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;
import p005b.p113c0.p114a.p130l.C1489a;
import p005b.p113c0.p114a.p130l.C1494f;
import p005b.p113c0.p114a.p130l.C1495g;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.c0.a.h.m.c */
/* loaded from: classes2.dex */
public class C1453c extends AbstractC1451a implements InterfaceC1498j {

    /* renamed from: f */
    public final String f1407f;

    public C1453c(@NonNull String str, @NonNull String str2) {
        super(str2);
        C2354n.m2426R0(!TextUtils.isEmpty(str), "The rootPath cannot be empty.");
        C2354n.m2426R0(str.matches(InterfaceC1498j.f1517c), "The format of [%s] is wrong, it should be like [/root/project].");
        this.f1407f = str;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a
    /* renamed from: b */
    public boolean mo499b(@NonNull InterfaceC1457c interfaceC1457c) {
        return m517i(interfaceC1457c.getPath()) != null;
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d, p005b.p113c0.p114a.p116h.InterfaceC1428d
    /* renamed from: d */
    public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
        File m517i = m517i(interfaceC1457c.getPath());
        if (m517i != null) {
            return m517i.lastModified();
        }
        return -1L;
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d, p005b.p113c0.p114a.p116h.InterfaceC1425a
    /* renamed from: e */
    public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
        File m517i = m517i(interfaceC1457c.getPath());
        if (m517i == null) {
            return null;
        }
        return C1489a.m559a(m517i.getAbsolutePath() + m517i.lastModified());
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d
    @NonNull
    /* renamed from: g */
    public InterfaceC1463i mo515g(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        String sb;
        String path = interfaceC1457c.getPath();
        File file = new File(this.f1407f, path);
        if (file.exists() && file.isFile()) {
            return new C1431a(file);
        }
        File file2 = new File(file, this.f1405e);
        if (!file2.exists() || !file2.isFile()) {
            throw new C1421g(path);
        }
        if (path.endsWith(File.separator)) {
            return new C1431a(file2);
        }
        String m514h = m514h(path);
        C1494f c1494f = (C1494f) interfaceC1457c.mo524e();
        if (c1494f.isEmpty()) {
            sb = "";
        } else {
            StringBuilder sb2 = new StringBuilder();
            Iterator it = c1494f.entrySet().iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                Map.Entry entry = (Map.Entry) it.next();
                String str = (String) entry.getKey();
                List list = (List) entry.getValue();
                if (list != null && !list.isEmpty()) {
                    for (int i2 = 0; i2 < list.size(); i2++) {
                        C1499a.m606a0(sb2, "&", str, "=");
                        sb2.append((String) list.get(i2));
                    }
                }
            }
            if (sb2.length() > 0) {
                sb2.deleteCharAt(0);
            }
            sb = sb2.toString();
        }
        String m639y = C1499a.m639y(m514h, "?", sb);
        C1466l c1466l = (C1466l) interfaceC1458d;
        c1466l.f1437b.mo5529i(302);
        c1466l.f1437b.mo5520o("Location", m639y);
        return new C1432b("", C1495g.f1510k);
    }

    /* renamed from: i */
    public final File m517i(@NonNull String str) {
        File file = new File(this.f1407f, str);
        if (file.exists() && file.isFile()) {
            return file;
        }
        File file2 = new File(file, this.f1405e);
        if (file2.exists() && file2.isFile()) {
            return file2;
        }
        return null;
    }
}
