package H2;

import B2.A;
import java.net.ProtocolException;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f1094d = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final A f1095a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f1096b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final String f1097c;

    public static final class a {
        private a() {
        }

        public final k a(String str) throws ProtocolException {
            A a3;
            int i3;
            String strSubstring;
            t2.j.f(str, "statusLine");
            if (z2.g.u(str, "HTTP/1.", false, 2, null)) {
                i3 = 9;
                if (str.length() < 9 || str.charAt(8) != ' ') {
                    throw new ProtocolException("Unexpected status line: " + str);
                }
                int iCharAt = str.charAt(7) - '0';
                if (iCharAt == 0) {
                    a3 = A.HTTP_1_0;
                } else {
                    if (iCharAt != 1) {
                        throw new ProtocolException("Unexpected status line: " + str);
                    }
                    a3 = A.HTTP_1_1;
                }
            } else {
                if (!z2.g.u(str, "ICY ", false, 2, null)) {
                    throw new ProtocolException("Unexpected status line: " + str);
                }
                a3 = A.HTTP_1_0;
                i3 = 4;
            }
            int i4 = i3 + 3;
            if (str.length() < i4) {
                throw new ProtocolException("Unexpected status line: " + str);
            }
            try {
                String strSubstring2 = str.substring(i3, i4);
                t2.j.e(strSubstring2, "(this as java.lang.Strin…ing(startIndex, endIndex)");
                int i5 = Integer.parseInt(strSubstring2);
                if (str.length() <= i4) {
                    strSubstring = "";
                } else {
                    if (str.charAt(i4) != ' ') {
                        throw new ProtocolException("Unexpected status line: " + str);
                    }
                    strSubstring = str.substring(i3 + 4);
                    t2.j.e(strSubstring, "(this as java.lang.String).substring(startIndex)");
                }
                return new k(a3, i5, strSubstring);
            } catch (NumberFormatException unused) {
                throw new ProtocolException("Unexpected status line: " + str);
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public k(A a3, int i3, String str) {
        t2.j.f(a3, "protocol");
        t2.j.f(str, "message");
        this.f1095a = a3;
        this.f1096b = i3;
        this.f1097c = str;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (this.f1095a == A.HTTP_1_0) {
            sb.append("HTTP/1.0");
        } else {
            sb.append("HTTP/1.1");
        }
        sb.append(' ');
        sb.append(this.f1096b);
        sb.append(' ');
        sb.append(this.f1097c);
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }
}
