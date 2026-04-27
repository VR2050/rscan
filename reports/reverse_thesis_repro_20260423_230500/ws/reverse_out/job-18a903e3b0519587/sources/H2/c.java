package H2;

import h2.r;
import java.text.DateFormat;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public abstract class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final a f1073a = new a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final String[] f1074b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final DateFormat[] f1075c;

    public static final class a extends ThreadLocal {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // java.lang.ThreadLocal
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public DateFormat initialValue() {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
            simpleDateFormat.setLenient(false);
            simpleDateFormat.setTimeZone(C2.c.f583f);
            return simpleDateFormat;
        }
    }

    static {
        String[] strArr = {"EEE, dd MMM yyyy HH:mm:ss zzz", "EEEE, dd-MMM-yy HH:mm:ss zzz", "EEE MMM d HH:mm:ss yyyy", "EEE, dd-MMM-yyyy HH:mm:ss z", "EEE, dd-MMM-yyyy HH-mm-ss z", "EEE, dd MMM yy HH:mm:ss z", "EEE dd-MMM-yyyy HH:mm:ss z", "EEE dd MMM yyyy HH:mm:ss z", "EEE dd-MMM-yyyy HH-mm-ss z", "EEE dd-MMM-yy HH:mm:ss z", "EEE dd MMM yy HH:mm:ss z", "EEE,dd-MMM-yy HH:mm:ss z", "EEE,dd-MMM-yyyy HH:mm:ss z", "EEE, dd-MM-yyyy HH:mm:ss z", "EEE MMM d yyyy HH:mm:ss z"};
        f1074b = strArr;
        f1075c = new DateFormat[strArr.length];
    }

    public static final Date a(String str) {
        t2.j.f(str, "$this$toHttpDateOrNull");
        if (str.length() == 0) {
            return null;
        }
        ParsePosition parsePosition = new ParsePosition(0);
        Date date = ((DateFormat) f1073a.get()).parse(str, parsePosition);
        if (parsePosition.getIndex() == str.length()) {
            return date;
        }
        String[] strArr = f1074b;
        synchronized (strArr) {
            try {
                int length = strArr.length;
                for (int i3 = 0; i3 < length; i3++) {
                    DateFormat[] dateFormatArr = f1075c;
                    DateFormat simpleDateFormat = dateFormatArr[i3];
                    if (simpleDateFormat == null) {
                        simpleDateFormat = new SimpleDateFormat(f1074b[i3], Locale.US);
                        simpleDateFormat.setTimeZone(C2.c.f583f);
                        dateFormatArr[i3] = simpleDateFormat;
                    }
                    parsePosition.setIndex(0);
                    Date date2 = simpleDateFormat.parse(str, parsePosition);
                    if (parsePosition.getIndex() != 0) {
                        return date2;
                    }
                }
                r rVar = r.f9288a;
                return null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static final String b(Date date) {
        t2.j.f(date, "$this$toHttpDateString");
        String str = ((DateFormat) f1073a.get()).format(date);
        t2.j.e(str, "STANDARD_DATE_FORMAT.get().format(this)");
        return str;
    }
}
