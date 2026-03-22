package p005b.p113c0.p114a.p124i.p125n;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.Serializable;

/* renamed from: b.c0.a.i.n.a */
/* loaded from: classes2.dex */
public class C1468a implements Cloneable, Serializable {

    /* renamed from: c */
    public String f1452c;

    /* renamed from: e */
    public String f1453e;

    /* renamed from: f */
    public String f1454f;

    /* renamed from: g */
    public boolean f1455g = false;

    public C1468a(@NonNull String str, @Nullable String str2) {
        boolean z;
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("The name of the cookie cannot be empty or null.");
        }
        int length = str.length();
        for (int i2 = 0; i2 < length; i2++) {
            char charAt = str.charAt(i2);
            if (charAt < ' ' || charAt >= 127 || "/()<>@,;:\\\"[]?={} \t".indexOf(charAt) != -1) {
                z = false;
                break;
            }
        }
        z = true;
        if (!z || str.equalsIgnoreCase("Comment") || str.equalsIgnoreCase("Discard") || str.equalsIgnoreCase("Domain") || str.equalsIgnoreCase("Expires") || str.equalsIgnoreCase("Max-Age") || str.equalsIgnoreCase("Path") || str.equalsIgnoreCase("Secure") || str.equalsIgnoreCase("Version") || str.startsWith("$")) {
            throw new IllegalArgumentException(String.format("This name [%1$s] is a reserved character.", str));
        }
        this.f1452c = str;
        this.f1453e = str2;
    }

    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e2) {
            throw new RuntimeException(e2.getMessage());
        }
    }
}
