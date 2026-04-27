package d1;

import android.net.Uri;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import java.util.List;
import java.util.ListIterator;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: renamed from: d1.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0507c extends RuntimeException {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f9154c = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final String f9155d = "\n\nTry the following to fix the issue:\n\\u2022 Ensure that Metro is running\n\\u2022 Ensure that your device/emulator is connected to your machine and has USB debugging enabled - run 'adb devices' to see a list of connected devices\n\\u2022 Ensure Airplane Mode is disabled\n\\u2022 If you're on a physical device connected to the same machine, run 'adb reverse tcp:<PORT> tcp:<PORT> to forward requests from your device\n\\u2022 If your device is on the same Wi-Fi network, set 'Debug server host & port for device' in 'Dev settings' to your machine's IP address and the port of the local dev server - e.g. 10.0.1.1:<PORT>\n\n";

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f9156b;

    /* JADX INFO: renamed from: d1.c$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final String d(String str) {
            List listG;
            List listC = new z2.f("/").c(str, 0);
            if (listC.isEmpty()) {
                listG = AbstractC0586n.g();
            } else {
                ListIterator listIterator = listC.listIterator(listC.size());
                while (listIterator.hasPrevious()) {
                    if (((String) listIterator.previous()).length() != 0) {
                        listG = AbstractC0586n.Q(listC, listIterator.nextIndex() + 1);
                        break;
                    }
                }
                listG = AbstractC0586n.g();
            }
            return (String) AbstractC0580h.x((String[]) listG.toArray(new String[0]));
        }

        public final C0507c a(String str, String str2, String str3, Throwable th) {
            t2.j.f(str, "url");
            t2.j.f(str2, "reason");
            t2.j.f(str3, "extra");
            return new C0507c(str2 + z2.g.q(C0507c.f9155d, "<PORT>", String.valueOf(Uri.parse(str).getPort()), false, 4, null) + str3, th);
        }

        public final C0507c b(String str, String str2, Throwable th) {
            t2.j.f(str, "url");
            t2.j.f(str2, "reason");
            return a(str, str2, "", th);
        }

        public final C0507c c(String str, String str2) {
            if (str2 != null && str2.length() != 0) {
                try {
                    JSONObject jSONObject = new JSONObject(str2);
                    String string = jSONObject.getString("filename");
                    String string2 = jSONObject.getString("message");
                    t2.j.e(string2, "getString(...)");
                    t2.j.c(string);
                    return new C0507c(string2, d(string), jSONObject.getInt("lineNumber"), jSONObject.getInt("column"), null);
                } catch (JSONException e3) {
                    Y.a.J("ReactNative", "Could not parse DebugServerException from: " + str2, e3);
                }
            }
            return null;
        }

        private a() {
        }
    }

    public /* synthetic */ C0507c(String str, String str2, int i3, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, i3, i4);
    }

    public static final C0507c b(String str, String str2, String str3, Throwable th) {
        return f9154c.a(str, str2, str3, th);
    }

    public static final C0507c c(String str, String str2, Throwable th) {
        return f9154c.b(str, str2, th);
    }

    public static final C0507c d(String str, String str2) {
        return f9154c.c(str, str2);
    }

    private C0507c(String str, String str2, int i3, int i4) {
        super(str + "\n  at " + str2 + ":" + i3 + ":" + i4);
        this.f9156b = str;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0507c(String str) {
        super(str);
        t2.j.f(str, "description");
        this.f9156b = str;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0507c(String str, Throwable th) {
        super(str, th);
        t2.j.f(str, "detailMessage");
        this.f9156b = str;
    }
}
