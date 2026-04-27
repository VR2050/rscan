package p;

import android.util.Base64;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f9745a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f9746b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f9747c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f9748d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f9749e = 0;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f9750f;

    public e(String str, String str2, String str3, List list) {
        this.f9745a = (String) q.g.f(str);
        this.f9746b = (String) q.g.f(str2);
        this.f9747c = (String) q.g.f(str3);
        this.f9748d = (List) q.g.f(list);
        this.f9750f = a(str, str2, str3);
    }

    private String a(String str, String str2, String str3) {
        return str + "-" + str2 + "-" + str3;
    }

    public List b() {
        return this.f9748d;
    }

    public int c() {
        return this.f9749e;
    }

    String d() {
        return this.f9750f;
    }

    public String e() {
        return this.f9745a;
    }

    public String f() {
        return this.f9746b;
    }

    public String g() {
        return this.f9747c;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FontRequest {mProviderAuthority: " + this.f9745a + ", mProviderPackage: " + this.f9746b + ", mQuery: " + this.f9747c + ", mCertificates:");
        for (int i3 = 0; i3 < this.f9748d.size(); i3++) {
            sb.append(" [");
            List list = (List) this.f9748d.get(i3);
            for (int i4 = 0; i4 < list.size(); i4++) {
                sb.append(" \"");
                sb.append(Base64.encodeToString((byte[]) list.get(i4), 0));
                sb.append("\"");
            }
            sb.append(" ]");
        }
        sb.append("}");
        sb.append("mCertificatesArray: " + this.f9749e);
        return sb.toString();
    }
}
