package z2;

import java.io.IOException;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class h {
    public static void a(Appendable appendable, Object obj, s2.l lVar) throws IOException {
        t2.j.f(appendable, "<this>");
        if (lVar != null) {
            appendable.append((CharSequence) lVar.d(obj));
            return;
        }
        if (obj == null ? true : obj instanceof CharSequence) {
            appendable.append((CharSequence) obj);
        } else if (obj instanceof Character) {
            appendable.append(((Character) obj).charValue());
        } else {
            appendable.append(String.valueOf(obj));
        }
    }
}
