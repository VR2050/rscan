package io.openinstall.sdk;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Base64;
import com.king.zxing.util.LogUtils;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import kotlin.UByte;

/* JADX INFO: loaded from: classes3.dex */
public class ay {
    private static ay k;
    private static final Object l = new Object();
    private final Context a;
    private final at b;
    private final String c;
    private final String d = Build.VERSION.RELEASE;
    private final Integer e;
    private final String f;
    private final String g;
    private final String h;
    private final String i;
    private final String j;
    private String m;
    private String n;
    private String o;

    private ay(Context context, at atVar) {
        Integer numValueOf;
        this.a = context;
        this.b = atVar;
        this.c = context.getPackageName();
        String str = null;
        try {
            PackageInfo packageInfo = this.a.getPackageManager().getPackageInfo(this.a.getPackageName(), 0);
            numValueOf = Integer.valueOf(packageInfo.versionCode);
            try {
                str = packageInfo.versionName;
            } catch (PackageManager.NameNotFoundException e) {
            }
        } catch (PackageManager.NameNotFoundException e2) {
            numValueOf = null;
        }
        this.e = numValueOf;
        this.f = str;
        this.g = Build.MODEL;
        this.h = Build.ID;
        this.i = Build.DISPLAY;
        this.j = Build.BRAND;
    }

    public static ay a(Context context, at atVar) {
        synchronized (l) {
            if (k == null) {
                k = new ay(context.getApplicationContext(), atVar);
            }
        }
        return k;
    }

    private boolean a(String str) {
        return TextUtils.isEmpty(str) || str.equalsIgnoreCase(dx.m);
    }

    private boolean b(String str) {
        return TextUtils.isEmpty(str) || str.equalsIgnoreCase(dx.i) || str.equalsIgnoreCase(dx.m);
    }

    public String a() {
        String str = this.m;
        if (str != null) {
            return str;
        }
        String strF = this.b.f();
        if (TextUtils.isEmpty(strF)) {
            try {
                strF = Settings.Secure.getString(this.a.getContentResolver(), "android_id");
            } catch (Throwable th) {
            }
        }
        if (b(strF)) {
            this.b.d(dx.m);
            strF = "";
        } else {
            this.b.d(strF);
        }
        this.m = strF;
        return this.m;
    }

    public String b() {
        String str = this.n;
        if (str != null) {
            return str;
        }
        String strG = this.b.g();
        if (TextUtils.isEmpty(strG)) {
            if (Build.VERSION.SDK_INT < 26) {
                strG = Build.SERIAL;
            } else {
                try {
                    strG = Build.getSerial();
                } catch (SecurityException e) {
                } catch (Throwable th) {
                }
            }
        }
        if (a(strG)) {
            this.b.e(dx.m);
            strG = "";
        } else {
            this.b.e(strG);
        }
        this.n = strG;
        return this.n;
    }

    public String c() {
        String str = this.o;
        if (str != null) {
            return str;
        }
        try {
            byte[] bArrDigest = MessageDigest.getInstance("SHA1").digest(this.a.getPackageManager().getPackageInfo(this.a.getPackageName(), 64).signatures[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : bArrDigest) {
                String upperCase = Integer.toHexString(b & UByte.MAX_VALUE).toUpperCase(Locale.US);
                if (upperCase.length() == 1) {
                    sb.append("0");
                }
                sb.append(upperCase);
                sb.append(LogUtils.COLON);
            }
            String string = sb.toString();
            this.o = string.substring(0, string.length() - 1);
        } catch (PackageManager.NameNotFoundException e) {
        } catch (NoSuchAlgorithmException e2) {
        } catch (Throwable th) {
        }
        return this.o;
    }

    public String d() {
        return this.c;
    }

    public String e() {
        return this.d;
    }

    public Integer f() {
        return this.e;
    }

    public String g() {
        return this.f;
    }

    public String h() {
        return this.g;
    }

    public String i() {
        return this.h;
    }

    public String j() {
        return this.i;
    }

    public String k() {
        return this.j;
    }

    public String l() {
        FileChannel channel;
        try {
            channel = new RandomAccessFile(this.a.getApplicationInfo().sourceDir, "r").getChannel();
            try {
                cb cbVarA = cc.a(channel);
                if (cbVarA == null) {
                    if (channel != null) {
                        try {
                            channel.close();
                        } catch (IOException e) {
                        }
                    }
                    return "";
                }
                byte[] bArrC = cbVarA.c();
                if (bArrC == null) {
                    if (channel != null) {
                        try {
                            channel.close();
                        } catch (IOException e2) {
                        }
                    }
                    return "";
                }
                String str = new String(Base64.encode(bArrC, 10), bu.c);
                if (channel != null) {
                    try {
                        channel.close();
                    } catch (IOException e3) {
                    }
                }
                return str;
            } catch (IOException e4) {
                if (channel == null) {
                    return null;
                }
                try {
                    channel.close();
                    return null;
                } catch (IOException e5) {
                    return null;
                }
            } catch (Throwable th) {
                if (channel == null) {
                    return null;
                }
                channel.close();
                return null;
            }
        } catch (IOException e6) {
            channel = null;
        } catch (Throwable th2) {
            channel = null;
        }
    }

    public List<String> m() {
        ArrayList arrayList = new ArrayList();
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            if (networkInterfaces != null) {
                while (networkInterfaces.hasMoreElements()) {
                    NetworkInterface networkInterfaceNextElement = networkInterfaces.nextElement();
                    if (!networkInterfaceNextElement.isLoopback() && networkInterfaceNextElement.isUp() && !networkInterfaceNextElement.getName().startsWith("dummy")) {
                        Enumeration<InetAddress> inetAddresses = networkInterfaceNextElement.getInetAddresses();
                        while (inetAddresses.hasMoreElements()) {
                            InetAddress inetAddressNextElement = inetAddresses.nextElement();
                            if (inetAddressNextElement instanceof Inet4Address) {
                                arrayList.add(inetAddressNextElement.getHostAddress());
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
        } catch (Throwable th) {
        }
        return arrayList;
    }
}
