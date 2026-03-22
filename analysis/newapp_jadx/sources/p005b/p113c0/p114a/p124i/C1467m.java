package p005b.p113c0.p114a.p124i;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import p005b.p113c0.p114a.p130l.C1494f;
import p005b.p113c0.p114a.p130l.InterfaceC1497i;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p478a.p483b.C4784a;

/* renamed from: b.c0.a.i.m */
/* loaded from: classes2.dex */
public class C1467m implements InterfaceC1498j {

    /* renamed from: e */
    public static final /* synthetic */ int f1439e = 0;

    /* renamed from: f */
    public final String f1440f;

    /* renamed from: g */
    public final String f1441g;

    /* renamed from: h */
    public final int f1442h;

    /* renamed from: i */
    public final String f1443i;

    /* renamed from: j */
    public final String f1444j;

    /* renamed from: k */
    public final String f1445k;

    /* renamed from: b.c0.a.i.m$b */
    public static class b {

        /* renamed from: a */
        public String f1446a;

        /* renamed from: b */
        public String f1447b;

        /* renamed from: c */
        public int f1448c;

        /* renamed from: d */
        public List<String> f1449d;

        /* renamed from: e */
        public InterfaceC1497i<String, String> f1450e;

        /* renamed from: f */
        public String f1451f;

        public b(String str, a aVar) {
            URI create = URI.create(str);
            this.f1446a = create.getScheme();
            this.f1447b = create.getHost();
            this.f1448c = create.getPort();
            this.f1449d = C1467m.m546a(create.getPath());
            this.f1450e = C1467m.m547b(create.getRawQuery());
            this.f1451f = create.getFragment();
        }
    }

    public C1467m(b bVar, a aVar) {
        String str;
        this.f1440f = bVar.f1446a;
        this.f1441g = bVar.f1447b;
        this.f1442h = bVar.f1448c;
        List<String> list = bVar.f1449d;
        if (list == null || list.isEmpty()) {
            str = "";
        } else {
            StringBuilder sb = new StringBuilder();
            for (String str2 : list) {
                sb.append("/");
                sb.append(str2);
            }
            str = sb.toString();
            while (str.contains("//")) {
                str = str.replace("//", "/");
            }
        }
        this.f1443i = str;
        InterfaceC1497i<String, String> interfaceC1497i = bVar.f1450e;
        StringBuilder sb2 = new StringBuilder();
        Iterator it = ((C1494f) interfaceC1497i).entrySet().iterator();
        if (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            String str3 = (String) entry.getKey();
            List<String> list2 = (List) entry.getValue();
            if (list2 == null || list2.isEmpty()) {
                sb2.append(str3);
                sb2.append("=");
            } else {
                for (String str4 : list2) {
                    sb2.append(str3);
                    sb2.append("=");
                    try {
                        str4 = URLEncoder.encode(str4, "utf-8");
                    } catch (UnsupportedEncodingException unused) {
                    }
                    sb2.append(str4);
                }
            }
        }
        while (it.hasNext()) {
            Map.Entry entry2 = (Map.Entry) it.next();
            String str5 = (String) entry2.getKey();
            List<String> list3 = (List) entry2.getValue();
            if (list3 == null || list3.isEmpty()) {
                C1499a.m606a0(sb2, "&", str5, "=");
            } else {
                for (String str6 : list3) {
                    C1499a.m606a0(sb2, "&", str5, "=");
                    try {
                        str6 = URLEncoder.encode(str6, "utf-8");
                    } catch (UnsupportedEncodingException unused2) {
                    }
                    sb2.append(str6);
                }
            }
        }
        this.f1444j = sb2.toString();
        this.f1445k = bVar.f1451f;
    }

    /* renamed from: a */
    public static List<String> m546a(String str) {
        LinkedList linkedList = new LinkedList();
        if (TextUtils.isEmpty(str)) {
            return linkedList;
        }
        while (str.contains("//")) {
            str = str.replace("//", "/");
        }
        while (str.contains("/")) {
            if (str.startsWith("/")) {
                linkedList.add("");
                str = str.substring(1);
            } else {
                int indexOf = str.indexOf("/");
                linkedList.add(str.substring(0, indexOf));
                str = str.substring(indexOf + 1);
            }
            if (!str.contains("/")) {
                linkedList.add(str);
            }
        }
        return linkedList;
    }

    /* renamed from: b */
    public static InterfaceC1497i<String, String> m547b(String str) {
        C1494f c1494f = new C1494f();
        if (!TextUtils.isEmpty(str)) {
            if (str.startsWith("?")) {
                str = str.substring(1);
            }
            StringTokenizer stringTokenizer = new StringTokenizer(str, "&");
            while (stringTokenizer.hasMoreElements()) {
                String nextToken = stringTokenizer.nextToken();
                int indexOf = nextToken.indexOf("=");
                if (indexOf > 0 && indexOf < nextToken.length() - 1) {
                    String substring = nextToken.substring(0, indexOf);
                    String substring2 = nextToken.substring(indexOf + 1);
                    try {
                        substring2 = URLDecoder.decode(substring2, C4784a.m5463a("utf-8").name());
                    } catch (UnsupportedEncodingException unused) {
                    }
                    c1494f.m566a(substring, substring2);
                }
            }
        }
        return c1494f;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (!TextUtils.isEmpty(this.f1440f)) {
            sb.append(this.f1440f);
            sb.append(":");
        }
        if (!TextUtils.isEmpty(this.f1441g) && this.f1442h > 0) {
            sb.append("//");
            sb.append(this.f1441g);
            sb.append(":");
            sb.append(this.f1442h);
        }
        if (!TextUtils.isEmpty(this.f1443i)) {
            sb.append(this.f1443i);
        }
        if (!TextUtils.isEmpty(this.f1444j)) {
            sb.append("?");
            sb.append(this.f1444j);
        }
        if (!TextUtils.isEmpty(this.f1445k)) {
            sb.append("#");
            sb.append(this.f1445k);
        }
        return sb.toString();
    }
}
