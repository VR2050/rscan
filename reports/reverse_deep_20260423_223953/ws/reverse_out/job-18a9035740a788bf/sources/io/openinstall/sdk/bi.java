package io.openinstall.sdk;

import android.content.Context;
import android.text.TextUtils;
import java.io.File;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class bi {
    private final File a;
    private final File b;
    private int c;

    public bi(Context context, String str) {
        this.a = new File(context.getFilesDir(), str);
        this.b = new File(context.getFilesDir(), str + ".t");
        this.c = a(this.a) + a(this.b);
    }

    private int a(File file) throws Throwable {
        String strB = bp.b(file);
        int length = 0;
        int i = 0;
        while (true) {
            int iIndexOf = strB.indexOf(";", length);
            if (iIndexOf == -1) {
                return i;
            }
            i++;
            length = iIndexOf + ";".length();
        }
    }

    private int a(String str, int i) {
        int length = 0;
        int i2 = 0;
        do {
            int iIndexOf = str.indexOf(";", length);
            if (iIndexOf == -1) {
                break;
            }
            i2++;
            length = ";".length() + iIndexOf;
        } while (i2 < i);
        return length;
    }

    private void a(String str) throws Throwable {
        bp.a(this.a, str, true);
        this.a.length();
    }

    private String b(be beVar) {
        StringBuilder sb = new StringBuilder();
        if (!TextUtils.isEmpty(beVar.d())) {
            sb.append(beVar.d());
            sb.append(",");
        }
        if (beVar.e() != null) {
            sb.append(beVar.e());
            sb.append(",");
        }
        if (beVar.f() != null) {
            sb.append(beVar.f());
            sb.append(",");
        }
        if (beVar.g() != null && beVar.g().size() > 0) {
            try {
                JSONObject jSONObject = new JSONObject();
                for (Map.Entry<String, String> entry : beVar.g().entrySet()) {
                    jSONObject.put(entry.getKey(), entry.getValue());
                }
                sb.append(dw.c(jSONObject.toString()));
                sb.append(",");
            } catch (JSONException e) {
            }
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
            sb.append(";");
        }
        String string = sb.toString();
        int length = string.getBytes(bu.c).length;
        return string;
    }

    public void a(be beVar) throws Throwable {
        a(b(beVar));
        this.c++;
    }

    public boolean a() {
        return this.c <= 0;
    }

    public boolean b() {
        return this.c >= 100;
    }

    public void c() throws Throwable {
        int iA = a(this.b);
        bp.a(this.b, "", false);
        this.c -= iA;
    }

    public void d() {
        this.a.delete();
        this.b.delete();
        this.c = 0;
    }

    public String e() throws Throwable {
        int iA = a(this.b);
        String strB = bp.b(this.b);
        if (iA > 50) {
            return strB;
        }
        String strB2 = bp.b(this.a);
        int iA2 = a(strB2, 100 - iA);
        String str = strB + strB2.substring(0, iA2);
        bp.a(this.b, str, false);
        bp.a(this.a, strB2.substring(iA2), false);
        return str;
    }
}
