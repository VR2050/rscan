package p476m.p477a.p485b.p494m0;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;

/* renamed from: m.a.b.m0.f */
/* loaded from: classes3.dex */
public class C4879f {

    /* renamed from: a */
    public static final TimeZone f12480a = TimeZone.getTimeZone("GMT");

    /* renamed from: b */
    public final DateFormat f12481b;

    /* renamed from: c */
    public long f12482c = 0;

    /* renamed from: d */
    public String f12483d = null;

    public C4879f() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        this.f12481b = simpleDateFormat;
        simpleDateFormat.setTimeZone(f12480a);
    }
}
