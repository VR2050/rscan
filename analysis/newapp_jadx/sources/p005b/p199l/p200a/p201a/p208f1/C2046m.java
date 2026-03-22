package p005b.p199l.p200a.p201a.p208f1;

import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.id3.CommentFrame;
import com.google.android.exoplayer2.metadata.id3.InternalFrame;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: b.l.a.a.f1.m */
/* loaded from: classes.dex */
public final class C2046m {

    /* renamed from: a */
    public static final Pattern f4169a = Pattern.compile("^ [0-9a-fA-F]{8} ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})");

    /* renamed from: b */
    public int f4170b = -1;

    /* renamed from: c */
    public int f4171c = -1;

    /* renamed from: a */
    public final boolean m1630a(String str) {
        Matcher matcher = f4169a.matcher(str);
        if (!matcher.find()) {
            return false;
        }
        try {
            int parseInt = Integer.parseInt(matcher.group(1), 16);
            int parseInt2 = Integer.parseInt(matcher.group(2), 16);
            if (parseInt <= 0 && parseInt2 <= 0) {
                return false;
            }
            this.f4170b = parseInt;
            this.f4171c = parseInt2;
            return true;
        } catch (NumberFormatException unused) {
            return false;
        }
    }

    /* renamed from: b */
    public boolean m1631b(Metadata metadata) {
        int i2 = 0;
        while (true) {
            Metadata.Entry[] entryArr = metadata.f9273c;
            if (i2 >= entryArr.length) {
                return false;
            }
            Metadata.Entry entry = entryArr[i2];
            if (entry instanceof CommentFrame) {
                CommentFrame commentFrame = (CommentFrame) entry;
                if ("iTunSMPB".equals(commentFrame.f9318f) && m1630a(commentFrame.f9319g)) {
                    return true;
                }
            } else if (entry instanceof InternalFrame) {
                InternalFrame internalFrame = (InternalFrame) entry;
                if ("com.apple.iTunes".equals(internalFrame.f9325e) && "iTunSMPB".equals(internalFrame.f9326f) && m1630a(internalFrame.f9327g)) {
                    return true;
                }
            } else {
                continue;
            }
            i2++;
        }
    }
}
