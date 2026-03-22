package p458k.p459p0.p463g;

import java.text.DateFormat;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.p459p0.C4401c;

/* renamed from: k.p0.g.c */
/* loaded from: classes3.dex */
public final class C4426c {

    /* renamed from: a */
    public static final a f11731a = new a();

    /* renamed from: b */
    public static final String[] f11732b;

    /* renamed from: c */
    public static final DateFormat[] f11733c;

    /* renamed from: k.p0.g.c$a */
    public static final class a extends ThreadLocal<DateFormat> {
        @Override // java.lang.ThreadLocal
        public DateFormat initialValue() {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
            simpleDateFormat.setLenient(false);
            simpleDateFormat.setTimeZone(C4401c.f11560e);
            return simpleDateFormat;
        }
    }

    static {
        String[] strArr = {"EEE, dd MMM yyyy HH:mm:ss zzz", "EEEE, dd-MMM-yy HH:mm:ss zzz", "EEE MMM d HH:mm:ss yyyy", "EEE, dd-MMM-yyyy HH:mm:ss z", "EEE, dd-MMM-yyyy HH-mm-ss z", "EEE, dd MMM yy HH:mm:ss z", "EEE dd-MMM-yyyy HH:mm:ss z", "EEE dd MMM yyyy HH:mm:ss z", "EEE dd-MMM-yyyy HH-mm-ss z", "EEE dd-MMM-yy HH:mm:ss z", "EEE dd MMM yy HH:mm:ss z", "EEE,dd-MMM-yy HH:mm:ss z", "EEE,dd-MMM-yyyy HH:mm:ss z", "EEE, dd-MM-yyyy HH:mm:ss z", "EEE MMM d yyyy HH:mm:ss z"};
        f11732b = strArr;
        f11733c = new DateFormat[strArr.length];
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v0, types: [java.text.DateFormat[]] */
    /* JADX WARN: Type inference failed for: r7v0 */
    @Nullable
    /* renamed from: a */
    public static final Date m5126a(@NotNull String toHttpDateOrNull) {
        Intrinsics.checkParameterIsNotNull(toHttpDateOrNull, "$this$toHttpDateOrNull");
        if (toHttpDateOrNull.length() == 0) {
            return null;
        }
        ParsePosition parsePosition = new ParsePosition(0);
        Date parse = f11731a.get().parse(toHttpDateOrNull, parsePosition);
        if (parsePosition.getIndex() == toHttpDateOrNull.length()) {
            return parse;
        }
        String[] strArr = f11732b;
        synchronized (strArr) {
            int length = strArr.length;
            for (int i2 = 0; i2 < length; i2++) {
                ?? r6 = f11733c;
                ?? r7 = r6[i2];
                SimpleDateFormat simpleDateFormat = r7;
                if (r7 == 0) {
                    SimpleDateFormat simpleDateFormat2 = new SimpleDateFormat(f11732b[i2], Locale.US);
                    simpleDateFormat2.setTimeZone(C4401c.f11560e);
                    r6[i2] = simpleDateFormat2;
                    simpleDateFormat = simpleDateFormat2;
                }
                parsePosition.setIndex(0);
                Date parse2 = simpleDateFormat.parse(toHttpDateOrNull, parsePosition);
                if (parsePosition.getIndex() != 0) {
                    return parse2;
                }
            }
            Unit unit = Unit.INSTANCE;
            return null;
        }
    }
}
