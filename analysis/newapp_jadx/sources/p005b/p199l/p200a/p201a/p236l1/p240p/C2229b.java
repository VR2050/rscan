package p005b.p199l.p200a.p201a.p236l1.p240p;

import android.text.TextUtils;
import androidx.annotation.Nullable;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.p.b */
/* loaded from: classes.dex */
public final class C2229b {

    /* renamed from: a */
    public final int f5470a;

    /* renamed from: b */
    public final int f5471b;

    /* renamed from: c */
    public final int f5472c;

    /* renamed from: d */
    public final int f5473d;

    /* renamed from: e */
    public final int f5474e;

    public C2229b(int i2, int i3, int i4, int i5, int i6) {
        this.f5470a = i2;
        this.f5471b = i3;
        this.f5472c = i4;
        this.f5473d = i5;
        this.f5474e = i6;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Nullable
    /* renamed from: a */
    public static C2229b m2093a(String str) {
        char c2;
        C4195m.m4765F(str.startsWith("Format:"));
        String[] split = TextUtils.split(str.substring(7), ChineseToPinyinResource.Field.COMMA);
        int i2 = -1;
        int i3 = -1;
        int i4 = -1;
        int i5 = -1;
        for (int i6 = 0; i6 < split.length; i6++) {
            String m2320L = C2344d0.m2320L(split[i6].trim());
            m2320L.hashCode();
            switch (m2320L.hashCode()) {
                case 100571:
                    if (m2320L.equals("end")) {
                        c2 = 0;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 3556653:
                    if (m2320L.equals("text")) {
                        c2 = 1;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 109757538:
                    if (m2320L.equals("start")) {
                        c2 = 2;
                        break;
                    }
                    c2 = 65535;
                    break;
                case 109780401:
                    if (m2320L.equals("style")) {
                        c2 = 3;
                        break;
                    }
                    c2 = 65535;
                    break;
                default:
                    c2 = 65535;
                    break;
            }
            if (c2 == 0) {
                i3 = i6;
            } else if (c2 == 1) {
                i5 = i6;
            } else if (c2 == 2) {
                i2 = i6;
            } else if (c2 == 3) {
                i4 = i6;
            }
        }
        if (i2 == -1 || i3 == -1) {
            return null;
        }
        return new C2229b(i2, i3, i4, i5, split.length);
    }
}
