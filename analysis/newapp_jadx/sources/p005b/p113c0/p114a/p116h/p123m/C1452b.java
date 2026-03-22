package p005b.p113c0.p114a.p116h.p123m;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.File;
import java.io.FileOutputStream;
import p005b.p113c0.p114a.p115g.C1421g;
import p005b.p113c0.p114a.p116h.p117g.C1431a;
import p005b.p113c0.p114a.p116h.p117g.C1432b;
import p005b.p113c0.p114a.p124i.C1466l;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;
import p005b.p113c0.p114a.p130l.C1489a;
import p005b.p113c0.p114a.p130l.C1495g;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p478a.p483b.C4784a;

/* renamed from: b.c0.a.h.m.b */
/* loaded from: classes2.dex */
public class C1452b extends AbstractC1451a implements InterfaceC1498j {

    /* renamed from: f */
    public final String f1406f;

    /* renamed from: b.c0.a.h.m.b$a */
    public class a extends C1431a {
        public a(C1452b c1452b, File file) {
            super(file);
        }

        @Override // p005b.p113c0.p114a.p116h.p117g.C1431a, p005b.p113c0.p114a.p124i.InterfaceC1463i
        @Nullable
        /* renamed from: c */
        public C1495g mo496c() {
            C1495g mo496c = super.mo496c();
            return mo496c != null ? new C1495g(mo496c.f1512e, mo496c.f1513f, C4784a.m5463a("utf-8")) : mo496c;
        }
    }

    public C1452b(String str) {
        C2354n.m2426R0(!TextUtils.isEmpty(str), "The rootPath cannot be empty.");
        C2354n.m2426R0(str.matches(InterfaceC1498j.f1517c), "The format of [%s] is wrong, it should be like [/root/project].");
        this.f1406f = str;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1437a
    /* renamed from: b */
    public boolean mo499b(@NonNull InterfaceC1457c interfaceC1457c) {
        return m516i(interfaceC1457c.getPath()) != null;
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d, p005b.p113c0.p114a.p116h.InterfaceC1428d
    /* renamed from: d */
    public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
        File m516i = m516i(interfaceC1457c.getPath());
        if (m516i != null) {
            return m516i.lastModified();
        }
        return -1L;
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d, p005b.p113c0.p114a.p116h.InterfaceC1425a
    /* renamed from: e */
    public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
        File m516i = m516i(interfaceC1457c.getPath());
        if (m516i == null) {
            return null;
        }
        return C1489a.m559a(m516i.getAbsolutePath() + m516i.lastModified());
    }

    @Override // p005b.p113c0.p114a.p116h.p123m.AbstractC1454d
    @NonNull
    /* renamed from: g */
    public InterfaceC1463i mo515g(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        String path = interfaceC1457c.getPath();
        File file = new File(this.f1406f, path);
        if (!file.exists()) {
            throw new C1421g(path);
        }
        if (!file.isDirectory()) {
            return new C1431a(file);
        }
        if (!path.endsWith(File.separator)) {
            String m514h = m514h(path);
            C1466l c1466l = (C1466l) interfaceC1458d;
            c1466l.f1437b.mo5529i(302);
            c1466l.f1437b.mo5520o("Location", m514h);
            return new C1432b("", C1495g.f1510k);
        }
        File createTempFile = File.createTempFile("file_browser", ".html");
        FileOutputStream fileOutputStream = new FileOutputStream(createTempFile);
        String name = file.getName();
        fileOutputStream.write(String.format("<!DOCTYPE html><html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"/> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, user-scalable=no\"><metaname=\"format-detection\" content=\"telephone=no\"/> <title>%1$s</title><style>.center_horizontal{margin:0 auto;text-align:center;} *,*::after,*::before {box-sizing: border-box;margin: 0;padding: 0;}a:-webkit-any-link {color: -webkit-link;cursor: auto;text-decoration: underline;}ul {list-style: none;display: block;list-style-type: none;-webkit-margin-before: 1em;-webkit-margin-after: 1em;-webkit-margin-start: 0px;-webkit-margin-end: 0px;-webkit-padding-start: 40px;}li {display: list-item;text-align: -webkit-match-parent;margin-bottom: 5px;}</style></head><body><h1 class=\"center_horizontal\">%2$s</h1><ul>", name, name).getBytes("utf-8"));
        File[] listFiles = file.listFiles();
        if (listFiles != null && listFiles.length > 0) {
            for (File file2 : listFiles) {
                String absolutePath = file2.getAbsolutePath();
                String substring = absolutePath.substring(this.f1406f.length() + absolutePath.indexOf(this.f1406f));
                String str = File.separator;
                if (!substring.startsWith(str)) {
                    substring = C1499a.m637w(str, substring);
                }
                fileOutputStream.write(String.format("<li><a href=\"%1$s\">%2$s</a></li>", substring, file2.getName()).getBytes("utf-8"));
            }
        }
        fileOutputStream.write("</ul></body></html>".getBytes("utf-8"));
        try {
            fileOutputStream.close();
        } catch (Exception unused) {
        }
        return new a(this, createTempFile);
    }

    /* renamed from: i */
    public final File m516i(@NonNull String str) {
        File file = new File(this.f1406f, str);
        if (file.exists()) {
            return file;
        }
        return null;
    }
}
