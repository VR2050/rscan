package p005b.p113c0.p114a.p130l;

import com.google.android.material.badge.BadgeDrawable;

/* renamed from: b.c0.a.l.j */
/* loaded from: classes2.dex */
public interface InterfaceC1498j {

    /* renamed from: a */
    public static final String f1515a;

    /* renamed from: b */
    public static final String f1516b;

    /* renamed from: c */
    public static final String f1517c;

    /* renamed from: d */
    public static final String f1518d;

    static {
        String format = String.format("[a-zA-Z0-9_\\-\\.]%s", "*");
        f1515a = format;
        String format2 = String.format("[a-zA-Z0-9_\\-\\.]%s", BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX);
        f1516b = format2;
        f1517c = String.format("((/%s)|((/%s)+))|((/%s)+/)", format, format2, format2);
        String format3 = String.format("[a-zA-Z0-9_\\-\\.]%s", BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX);
        f1518d = format3;
        String.format("(%s)(=)(%s)", format3, "(.)*");
        String.format("!%s", format3);
        String.format("(%s)(!=)(%s)", format3, format2);
    }
}
