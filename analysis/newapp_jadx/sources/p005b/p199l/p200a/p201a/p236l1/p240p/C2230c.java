package p005b.p199l.p200a.p201a.p236l1.p240p;

import android.graphics.PointF;
import androidx.annotation.Nullable;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.l1.p.c */
/* loaded from: classes.dex */
public final class C2230c {

    /* renamed from: a */
    public final String f5475a;

    /* renamed from: b */
    public final int f5476b;

    /* renamed from: b.l.a.a.l1.p.c$a */
    public static final class a {

        /* renamed from: a */
        public final int f5477a;

        /* renamed from: b */
        public final int f5478b;

        /* renamed from: c */
        public final int f5479c;

        public a(int i2, int i3, int i4) {
            this.f5477a = i2;
            this.f5478b = i3;
            this.f5479c = i4;
        }
    }

    /* renamed from: b.l.a.a.l1.p.c$b */
    public static final class b {

        /* renamed from: a */
        public static final Pattern f5480a = Pattern.compile("\\{([^}]*)\\}");

        /* renamed from: b */
        public static final Pattern f5481b = Pattern.compile(C2344d0.m2332j("\\\\pos\\((%1$s),(%1$s)\\)", "\\s*\\d+(?:\\.\\d+)?\\s*"));

        /* renamed from: c */
        public static final Pattern f5482c = Pattern.compile(C2344d0.m2332j("\\\\move\\(%1$s,%1$s,(%1$s),(%1$s)(?:,%1$s,%1$s)?\\)", "\\s*\\d+(?:\\.\\d+)?\\s*"));

        /* renamed from: d */
        public static final Pattern f5483d = Pattern.compile("\\\\an(\\d+)");

        @Nullable
        /* renamed from: a */
        public static PointF m2095a(String str) {
            String group;
            String str2;
            Matcher matcher = f5481b.matcher(str);
            Matcher matcher2 = f5482c.matcher(str);
            boolean find = matcher.find();
            boolean find2 = matcher2.find();
            if (find) {
                str2 = matcher.group(1);
                group = matcher.group(2);
            } else {
                if (!find2) {
                    return null;
                }
                String group2 = matcher2.group(1);
                group = matcher2.group(2);
                str2 = group2;
            }
            Objects.requireNonNull(str2);
            float parseFloat = Float.parseFloat(str2.trim());
            Objects.requireNonNull(group);
            return new PointF(parseFloat, Float.parseFloat(group.trim()));
        }
    }

    public C2230c(String str, int i2) {
        this.f5475a = str;
        this.f5476b = i2;
    }

    /* renamed from: a */
    public static int m2094a(String str) {
        boolean z;
        try {
            int parseInt = Integer.parseInt(str.trim());
            switch (parseInt) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                    z = true;
                    break;
                default:
                    z = false;
                    break;
            }
            if (z) {
                return parseInt;
            }
            return -1;
        } catch (NumberFormatException unused) {
            return -1;
        }
    }
}
