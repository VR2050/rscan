package p005b.p113c0.p114a.p130l;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/* renamed from: b.c0.a.l.c */
/* loaded from: classes2.dex */
public final class C1491c {

    /* renamed from: a */
    public static final SimpleDateFormat[] f1499a;

    /* renamed from: b */
    public static final TimeZone f1500b;

    /* renamed from: c */
    public static final SimpleDateFormat f1501c;

    static {
        Locale locale = Locale.US;
        f1499a = new SimpleDateFormat[]{new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", locale), new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", locale), new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", locale)};
        TimeZone timeZone = TimeZone.getTimeZone("GMT");
        f1500b = timeZone;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", locale);
        f1501c = simpleDateFormat;
        simpleDateFormat.setTimeZone(timeZone);
    }

    /* renamed from: a */
    public static long m561a(String str) {
        Date date = null;
        for (SimpleDateFormat simpleDateFormat : f1499a) {
            try {
                date = simpleDateFormat.parse(str);
            } catch (ParseException unused) {
            }
        }
        if (date == null) {
            return -1L;
        }
        return date.getTime();
    }
}
