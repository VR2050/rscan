package p005b.p085c.p088b.p100j;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import androidx.appcompat.widget.ActivityChooserModel;
import com.alibaba.fastjson.asm.Opcodes;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.conscrypt.EvpMdRef;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.C1348e;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.EnumC1350g;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p091b.C1355a;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.j.h */
/* loaded from: classes.dex */
public class C1383h {

    /* renamed from: a */
    public static final String[] f1303a = {"10.1.5.1013151", "10.1.5.1013148"};

    /* renamed from: b.c.b.j.h$a */
    public static class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ Activity f1304c;

        public a(Activity activity) {
            this.f1304c = activity;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f1304c.finish();
        }
    }

    /* renamed from: b.c.b.j.h$b */
    public static final class b {

        /* renamed from: a */
        public final PackageInfo f1305a;

        /* renamed from: b */
        public final int f1306b;

        /* renamed from: c */
        public final String f1307c;

        public b(PackageInfo packageInfo, int i2, String str) {
            this.f1305a = packageInfo;
            this.f1306b = i2;
            this.f1307c = str;
        }

        /* renamed from: a */
        public boolean m453a() {
            return this.f1305a.versionCode < this.f1306b;
        }

        /* renamed from: b */
        public boolean m454b(C1373a c1373a) {
            Signature[] signatureArr = this.f1305a.signatures;
            if (signatureArr == null || signatureArr.length == 0) {
                return false;
            }
            for (Signature signature : signatureArr) {
                String m440d = C1383h.m440d(c1373a, signature.toByteArray());
                if (m440d != null && !TextUtils.equals(m440d, this.f1307c)) {
                    C1353c.m362c(c1373a, "biz", "PublicKeyUnmatch", String.format("Got %s, expected %s", m440d, this.f1307c));
                    return true;
                }
            }
            return false;
        }
    }

    /* renamed from: a */
    public static b m437a(C1373a c1373a, Context context, List<C1356a.b> list) {
        PackageInfo packageInfo;
        String str;
        if (list == null) {
            return null;
        }
        for (C1356a.b bVar : list) {
            if (bVar != null) {
                String str2 = bVar.f1215a;
                int i2 = bVar.f1216b;
                String str3 = bVar.f1217c;
                try {
                    packageInfo = context.getPackageManager().getPackageInfo(str2, Opcodes.CHECKCAST);
                } catch (Throwable th) {
                    C1353c.m362c(c1373a, "auth", "GetPackageInfoEx", th.getMessage());
                    packageInfo = null;
                }
                boolean z = false;
                if (packageInfo == null) {
                    str = "info == null";
                } else {
                    Signature[] signatureArr = packageInfo.signatures;
                    if (signatureArr == null) {
                        str = "info.signatures == null";
                    } else if (signatureArr.length <= 0) {
                        str = "info.signatures.length <= 0";
                    } else {
                        z = true;
                        str = "";
                    }
                }
                if (!z) {
                    C1353c.m362c(c1373a, "auth", "NotIncludeSignatures", str);
                }
                b bVar2 = (z && packageInfo != null) ? new b(packageInfo, i2, str3) : null;
                if (bVar2 != null && !bVar2.m454b(c1373a) && !bVar2.m453a()) {
                    return bVar2;
                }
            }
        }
        return null;
    }

    /* renamed from: b */
    public static String m438b(int i2) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i3 = 0; i3 < i2; i3++) {
            int nextInt = random.nextInt(3);
            if (nextInt == 0) {
                sb.append(String.valueOf((char) Math.round((Math.random() * 25.0d) + 65.0d)));
            } else if (nextInt == 1) {
                sb.append(String.valueOf((char) Math.round((Math.random() * 25.0d) + 97.0d)));
            } else if (nextInt == 2) {
                sb.append(String.valueOf(new Random().nextInt(10)));
            }
        }
        return sb.toString();
    }

    /* renamed from: c */
    public static String m439c(Context context, String str) {
        String str2 = "";
        try {
            String str3 = "";
            for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : ((ActivityManager) context.getApplicationContext().getSystemService(ActivityChooserModel.ATTRIBUTE_ACTIVITY)).getRunningAppProcesses()) {
                if (runningAppProcessInfo.processName.equals(str)) {
                    str3 = str3 + "#M";
                } else {
                    if (runningAppProcessInfo.processName.startsWith(str + ":")) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(str3);
                        sb.append("#");
                        sb.append(runningAppProcessInfo.processName.replace(str + ":", ""));
                        str3 = sb.toString();
                    }
                }
            }
            str2 = str3;
        } catch (Throwable unused) {
        }
        if (str2.length() > 0) {
            str2 = str2.substring(1);
        }
        return str2.length() == 0 ? "N" : str2;
    }

    /* renamed from: d */
    public static String m440d(C1373a c1373a, byte[] bArr) {
        BigInteger modulus;
        try {
            PublicKey publicKey = ((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bArr))).getPublicKey();
            if (!(publicKey instanceof RSAPublicKey) || (modulus = ((RSAPublicKey) publicKey).getModulus()) == null) {
                return null;
            }
            return modulus.toString(16);
        } catch (Exception e2) {
            C1353c.m363d(c1373a, "auth", "GetPublicKeyFromSignEx", e2);
            return null;
        }
    }

    /* renamed from: e */
    public static String m441e(String str, String str2, String str3) {
        try {
            int indexOf = str3.indexOf(str) + str.length();
            if (indexOf <= str.length()) {
                return "";
            }
            int indexOf2 = TextUtils.isEmpty(str2) ? 0 : str3.indexOf(str2, indexOf);
            return indexOf2 < 1 ? str3.substring(indexOf) : str3.substring(indexOf, indexOf2);
        } catch (Throwable unused) {
            return "";
        }
    }

    /* renamed from: f */
    public static Map<String, String> m442f(C1373a c1373a, String str) {
        HashMap hashMap = new HashMap(4);
        int indexOf = str.indexOf(63);
        if (indexOf != -1 && indexOf < str.length() - 1) {
            for (String str2 : str.substring(indexOf + 1).split("&")) {
                int indexOf2 = str2.indexOf(61, 1);
                if (indexOf2 != -1 && indexOf2 < str2.length() - 1) {
                    hashMap.put(str2.substring(0, indexOf2), m444h(c1373a, str2.substring(indexOf2 + 1)));
                }
            }
        }
        return hashMap;
    }

    /* renamed from: g */
    public static boolean m443g(C1373a c1373a, String str, Activity activity) {
        int parseInt;
        String substring;
        if (TextUtils.isEmpty(str)) {
            return true;
        }
        if (str.toLowerCase().startsWith("alipays://platformapi/startApp?".toLowerCase()) || str.toLowerCase().startsWith("intent://platformapi/startapp?".toLowerCase())) {
            try {
                b m437a = m437a(c1373a, activity, C1348e.f1168d);
                if (m437a != null && !m437a.m453a() && !m437a.m454b(c1373a)) {
                    if (str.startsWith("intent://platformapi/startapp")) {
                        str = str.replaceFirst("intent://platformapi/startapp\\?", "alipays://platformapi/startApp?");
                    }
                    activity.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(str)));
                }
            } catch (Throwable unused) {
            }
            return true;
        }
        if (TextUtils.equals(str, "sdklite://h5quit") || TextUtils.equals(str, "http://m.alipay.com/?action=h5quit")) {
            C1349f.f1170b = C1349f.m357b();
            activity.finish();
            return true;
        }
        if (!str.startsWith("sdklite://h5quit?result=")) {
            return false;
        }
        try {
            String substring2 = str.substring(str.indexOf("sdklite://h5quit?result=") + 24);
            parseInt = Integer.parseInt(substring2.substring(substring2.lastIndexOf("&end_code=") + 10));
        } catch (Exception unused2) {
            EnumC1350g m358a = EnumC1350g.m358a(4001);
            C1349f.f1170b = C1349f.m356a(m358a.f1179l, m358a.f1180m, "");
        }
        if (parseInt != 9000 && parseInt != 8000) {
            EnumC1350g m358a2 = EnumC1350g.m358a(4000);
            C1349f.f1170b = C1349f.m356a(m358a2.f1179l, m358a2.f1180m, "");
            activity.runOnUiThread(new a(activity));
            return true;
        }
        if (C1355a.f1195b) {
            StringBuilder sb = new StringBuilder();
            String decode = URLDecoder.decode(str);
            String decode2 = URLDecoder.decode(decode);
            String str2 = decode2.substring(decode2.indexOf("sdklite://h5quit?result=") + 24, decode2.lastIndexOf("&end_code=")).split("&return_url=")[0];
            int indexOf = decode.indexOf("&return_url=") + 12;
            sb.append(str2);
            sb.append("&return_url=");
            sb.append(decode.substring(indexOf, decode.indexOf("&", indexOf)));
            sb.append(decode.substring(decode.indexOf("&", indexOf)));
            substring = sb.toString();
        } else {
            String decode3 = URLDecoder.decode(str);
            substring = decode3.substring(decode3.indexOf("sdklite://h5quit?result=") + 24, decode3.lastIndexOf("&end_code="));
        }
        EnumC1350g m358a3 = EnumC1350g.m358a(parseInt);
        C1349f.f1170b = C1349f.m356a(m358a3.f1179l, m358a3.f1180m, substring);
        activity.runOnUiThread(new a(activity));
        return true;
    }

    /* renamed from: h */
    public static String m444h(C1373a c1373a, String str) {
        try {
            return URLDecoder.decode(str, "utf-8");
        } catch (UnsupportedEncodingException e2) {
            C1353c.m363d(c1373a, "biz", "H5PayDataAnalysisError", e2);
            return "";
        }
    }

    /* renamed from: i */
    public static Map<String, String> m445i(String str) {
        HashMap hashMap = new HashMap();
        for (String str2 : str.split("&")) {
            int indexOf = str2.indexOf("=", 1);
            if (-1 != indexOf) {
                hashMap.put(str2.substring(0, indexOf), URLDecoder.decode(str2.substring(indexOf + 1)));
            }
        }
        return hashMap;
    }

    /* renamed from: j */
    public static boolean m446j(Context context) {
        String str;
        try {
            PackageManager packageManager = context.getPackageManager();
            try {
                str = C1348e.f1168d.get(0).f1215a;
            } catch (Throwable unused) {
                str = "com.eg.android.AlipayGphone";
            }
            PackageInfo packageInfo = packageManager.getPackageInfo(str, 128);
            if (packageInfo == null) {
                return false;
            }
            return packageInfo.versionCode < 99;
        } catch (Throwable th) {
            C4195m.m4816l(th);
            return false;
        }
    }

    /* renamed from: k */
    public static boolean m447k(C1373a c1373a, Context context, List<C1356a.b> list) {
        try {
            for (C1356a.b bVar : list) {
                if (bVar != null) {
                    try {
                        if (context.getPackageManager().getPackageInfo(bVar.f1215a, 128) != null) {
                            return true;
                        }
                    } catch (PackageManager.NameNotFoundException unused) {
                        continue;
                    }
                }
            }
            return false;
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "CheckLaunchAppExistEx", th);
            return false;
        }
    }

    /* renamed from: l */
    public static String m448l() {
        String str = "Unavailable";
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader("/proc/version"), 256);
            try {
                String readLine = bufferedReader.readLine();
                bufferedReader.close();
                Matcher matcher = Pattern.compile("\\w+\\s+\\w+\\s+([^\\s]+)\\s+\\(([^\\s@]+(?:@[^\\s.]+)?)[^)]*\\)\\s+\\((?:[^(]*\\([^)]*\\))?[^)]*\\)\\s+([^\\s]+)\\s+(?:PREEMPT\\s+)?(.+)").matcher(readLine);
                if (matcher.matches() && matcher.groupCount() >= 4) {
                    str = matcher.group(1) + "\n" + matcher.group(2) + " " + matcher.group(3) + "\n" + matcher.group(4);
                }
            } catch (Throwable th) {
                bufferedReader.close();
                throw th;
            }
        } catch (IOException unused) {
        }
        int indexOf = str.indexOf("-");
        if (indexOf != -1) {
            str = str.substring(0, indexOf);
        }
        int indexOf2 = str.indexOf("\n");
        if (indexOf2 != -1) {
            str = str.substring(0, indexOf2);
        }
        return C1499a.m637w("Linux ", str);
    }

    /* renamed from: m */
    public static JSONObject m449m(String str) {
        try {
            return new JSONObject(str);
        } catch (Throwable unused) {
            return new JSONObject();
        }
    }

    /* renamed from: n */
    public static String m450n(Context context) {
        DisplayMetrics displayMetrics = new DisplayMetrics();
        ((WindowManager) context.getApplicationContext().getSystemService("window")).getDefaultDisplay().getMetrics(displayMetrics);
        return displayMetrics.widthPixels + "*" + displayMetrics.heightPixels;
    }

    /* renamed from: o */
    public static String m451o(String str) {
        try {
            Uri parse = Uri.parse(str);
            return String.format("%s%s", parse.getAuthority(), parse.getPath());
        } catch (Throwable th) {
            C4195m.m4816l(th);
            return "-";
        }
    }

    /* renamed from: p */
    public static String m452p(String str) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(EvpMdRef.MD5.JCA_NAME);
            messageDigest.update(str.getBytes());
            byte[] digest = messageDigest.digest();
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b2 : digest) {
                sb.append(Character.forDigit((b2 & 240) >> 4, 16));
                sb.append(Character.forDigit(b2 & 15, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException unused) {
            return "";
        }
    }
}
