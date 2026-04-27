package z2;

import i2.AbstractC0586n;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class f implements Serializable {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f10562c = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Pattern f10563b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public f(Pattern pattern) {
        t2.j.f(pattern, "nativePattern");
        this.f10563b = pattern;
    }

    public final boolean a(CharSequence charSequence) {
        t2.j.f(charSequence, "input");
        return this.f10563b.matcher(charSequence).matches();
    }

    public final String b(CharSequence charSequence, String str) {
        t2.j.f(charSequence, "input");
        t2.j.f(str, "replacement");
        String strReplaceAll = this.f10563b.matcher(charSequence).replaceAll(str);
        t2.j.e(strReplaceAll, "replaceAll(...)");
        return strReplaceAll;
    }

    public final List c(CharSequence charSequence, int i3) {
        t2.j.f(charSequence, "input");
        q.c0(i3);
        Matcher matcher = this.f10563b.matcher(charSequence);
        if (i3 == 1 || !matcher.find()) {
            return AbstractC0586n.b(charSequence.toString());
        }
        ArrayList arrayList = new ArrayList(i3 > 0 ? w2.d.e(i3, 10) : 10);
        int i4 = i3 - 1;
        int iEnd = 0;
        do {
            arrayList.add(charSequence.subSequence(iEnd, matcher.start()).toString());
            iEnd = matcher.end();
            if (i4 >= 0 && arrayList.size() == i4) {
                break;
            }
        } while (matcher.find());
        arrayList.add(charSequence.subSequence(iEnd, charSequence.length()).toString());
        return arrayList;
    }

    public String toString() {
        String string = this.f10563b.toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public f(String str) {
        t2.j.f(str, "pattern");
        Pattern patternCompile = Pattern.compile(str);
        t2.j.e(patternCompile, "compile(...)");
        this(patternCompile);
    }
}
