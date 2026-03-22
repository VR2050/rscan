package p005b.p113c0.p114a.p124i.p125n;

import androidx.work.WorkRequest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.BitSet;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/* renamed from: b.c0.a.i.n.c */
/* loaded from: classes2.dex */
public class C1470c implements InterfaceC1469b {

    /* renamed from: a */
    public static final ThreadLocal<DateFormat> f1456a;

    /* renamed from: b */
    public static final String f1457b;

    /* renamed from: c */
    public static final BitSet f1458c;

    /* renamed from: b.c0.a.i.n.c$a */
    public static class a extends ThreadLocal<DateFormat> {
        @Override // java.lang.ThreadLocal
        public DateFormat initialValue() {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd-MMM-yyyy HH:mm:ss z", Locale.US);
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            return simpleDateFormat;
        }
    }

    static {
        a aVar = new a();
        f1456a = aVar;
        f1457b = aVar.get().format(new Date(WorkRequest.MIN_BACKOFF_MILLIS));
        f1458c = new BitSet(128);
        for (char c2 = '0'; c2 <= '9'; c2 = (char) (c2 + 1)) {
            f1458c.set(c2);
        }
        for (char c3 = 'a'; c3 <= 'z'; c3 = (char) (c3 + 1)) {
            f1458c.set(c3);
        }
        for (char c4 = 'A'; c4 <= 'Z'; c4 = (char) (c4 + 1)) {
            f1458c.set(c4);
        }
        BitSet bitSet = f1458c;
        bitSet.set(46);
        bitSet.set(45);
    }
}
