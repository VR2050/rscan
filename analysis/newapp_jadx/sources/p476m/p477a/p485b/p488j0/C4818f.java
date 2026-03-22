package p476m.p477a.p485b.p488j0;

import com.shuyu.gsyvideoplayer.utils.NeuQuant;
import com.yalantis.ucrop.view.CropImageView;
import java.util.Locale;
import org.conscrypt.NativeConstants;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p485b.InterfaceC4797d0;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* renamed from: m.a.b.j0.f */
/* loaded from: classes3.dex */
public class C4818f implements InterfaceC4797d0 {

    /* renamed from: a */
    public static final C4818f f12318a = new C4818f();

    /* renamed from: b */
    public static final String[][] f12319b = {null, new String[3], new String[8], new String[8], new String[25], new String[8]};

    static {
        m5487b(200, "OK");
        m5487b(201, "Created");
        m5487b(202, "Accepted");
        m5487b(204, "No Content");
        m5487b(301, "Moved Permanently");
        m5487b(302, "Moved Temporarily");
        m5487b(304, "Not Modified");
        m5487b(400, "Bad Request");
        m5487b(401, "Unauthorized");
        m5487b(403, "Forbidden");
        m5487b(404, "Not Found");
        m5487b(CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION, "Internal Server Error");
        m5487b(501, "Not Implemented");
        m5487b(502, "Bad Gateway");
        m5487b(NeuQuant.prime4, "Service Unavailable");
        m5487b(100, "Continue");
        m5487b(307, "Temporary Redirect");
        m5487b(405, "Method Not Allowed");
        m5487b(409, "Conflict");
        m5487b(412, "Precondition Failed");
        m5487b(413, "Request Too Long");
        m5487b(414, "Request-URI Too Long");
        m5487b(415, "Unsupported Media Type");
        m5487b(IjkMediaCodecInfo.RANK_SECURE, "Multiple Choices");
        m5487b(303, "See Other");
        m5487b(305, "Use Proxy");
        m5487b(402, "Payment Required");
        m5487b(406, "Not Acceptable");
        m5487b(407, "Proxy Authentication Required");
        m5487b(NativeConstants.EVP_PKEY_EC, "Request Timeout");
        m5487b(101, "Switching Protocols");
        m5487b(203, "Non Authoritative Information");
        m5487b(205, "Reset Content");
        m5487b(206, "Partial Content");
        m5487b(504, "Gateway Timeout");
        m5487b(505, "Http Version Not Supported");
        m5487b(410, "Gone");
        m5487b(411, "Length Required");
        m5487b(416, "Requested Range Not Satisfiable");
        m5487b(417, "Expectation Failed");
        m5487b(102, "Processing");
        m5487b(207, "Multi-Status");
        m5487b(422, "Unprocessable Entity");
        m5487b(419, "Insufficient Space On Resource");
        m5487b(420, "Method Failure");
        m5487b(423, "Locked");
        m5487b(507, "Insufficient Storage");
        m5487b(424, "Failed Dependency");
    }

    /* renamed from: b */
    public static void m5487b(int i2, String str) {
        int i3 = i2 / 100;
        f12319b[i3][i2 - (i3 * 100)] = str;
    }

    @Override // p476m.p477a.p485b.InterfaceC4797d0
    /* renamed from: a */
    public String mo5472a(int i2, Locale locale) {
        boolean z = i2 >= 100 && i2 < 600;
        String m626l = C1499a.m626l("Unknown category for status code ", i2);
        if (!z) {
            throw new IllegalArgumentException(m626l);
        }
        int i3 = i2 / 100;
        int i4 = i2 - (i3 * 100);
        String[][] strArr = f12319b;
        if (strArr[i3].length > i4) {
            return strArr[i3][i4];
        }
        return null;
    }
}
