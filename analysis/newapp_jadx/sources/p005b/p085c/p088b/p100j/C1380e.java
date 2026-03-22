package p005b.p085c.p088b.p100j;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Pair;
import com.alipay.android.app.IAlixPay;
import com.alipay.android.app.IRemoteServiceCallback;
import java.util.HashMap;
import java.util.Map;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.j.e */
/* loaded from: classes.dex */
public class C1380e {

    /* renamed from: a */
    public Activity f1293a;

    /* renamed from: b */
    public volatile IAlixPay f1294b;

    /* renamed from: d */
    public boolean f1296d;

    /* renamed from: e */
    public c f1297e;

    /* renamed from: f */
    public final C1373a f1298f;

    /* renamed from: c */
    public final Object f1295c = IAlixPay.class;

    /* renamed from: g */
    public String f1299g = null;

    /* renamed from: b.c.b.j.e$a */
    public class a extends IRemoteServiceCallback.Stub {
        public a(C1379d c1379d) {
        }

        @Override // com.alipay.android.app.IRemoteServiceCallback
        public int getVersion() {
            return 3;
        }

        @Override // com.alipay.android.app.IRemoteServiceCallback
        public boolean isHideLoadingScreen() {
            return false;
        }

        @Override // com.alipay.android.app.IRemoteServiceCallback
        public void payEnd(boolean z, String str) {
        }

        @Override // com.alipay.android.app.IRemoteServiceCallback
        public void r03(String str, String str2, Map map) {
            C1353c.m367h(C1380e.this.f1298f, "wlt", str, str2);
        }

        @Override // com.alipay.android.app.IRemoteServiceCallback
        public void startActivity(String str, String str2, int i2, Bundle bundle) {
            Intent intent = new Intent("android.intent.action.MAIN", (Uri) null);
            if (bundle == null) {
                bundle = new Bundle();
            }
            try {
                bundle.putInt("CallingPid", i2);
                intent.putExtras(bundle);
            } catch (Exception e2) {
                C1353c.m363d(C1380e.this.f1298f, "biz", "ErrIntentEx", e2);
            }
            intent.setClassName(str, str2);
            try {
                ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
                ActivityManager.getMyMemoryState(runningAppProcessInfo);
                C1353c.m367h(C1380e.this.f1298f, "biz", "isFg", runningAppProcessInfo.processName + "|" + runningAppProcessInfo.importance + "|");
            } catch (Throwable unused) {
            }
            try {
                C1380e c1380e = C1380e.this;
                if (c1380e.f1293a != null) {
                    long elapsedRealtime = SystemClock.elapsedRealtime();
                    C1380e.this.f1293a.startActivity(intent);
                    C1353c.m367h(C1380e.this.f1298f, "biz", "stAct2", "" + (SystemClock.elapsedRealtime() - elapsedRealtime));
                } else {
                    C1353c.m362c(c1380e.f1298f, "biz", "ErrActNull", "");
                    Context context = C1380e.this.f1298f.f1249c;
                    if (context != null) {
                        context.startActivity(intent);
                    }
                }
                C1380e.this.f1297e.mo348b();
            } catch (Throwable th) {
                C1353c.m363d(C1380e.this.f1298f, "biz", "ErrActNull", th);
                throw th;
            }
        }
    }

    /* renamed from: b.c.b.j.e$b */
    public class b implements ServiceConnection {
        public b(C1379d c1379d) {
        }

        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            C1353c.m361b(C1380e.this.f1298f, "biz", "srvCon");
            synchronized (C1380e.this.f1295c) {
                C1380e.this.f1294b = IAlixPay.Stub.asInterface(iBinder);
                C1380e.this.f1295c.notify();
            }
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName componentName) {
            C1353c.m361b(C1380e.this.f1298f, "biz", "srvDis");
            C1380e.this.f1294b = null;
        }
    }

    /* renamed from: b.c.b.j.e$c */
    public interface c {
        /* renamed from: a */
        void mo347a();

        /* renamed from: b */
        void mo348b();
    }

    public C1380e(Activity activity, C1373a c1373a, c cVar) {
        this.f1293a = activity;
        this.f1298f = c1373a;
        this.f1297e = cVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: a */
    public final Pair<String, Boolean> m427a(String str, String str2, C1373a c1373a) {
        int i2;
        b bVar;
        Activity activity;
        long elapsedRealtime;
        int i3;
        IRemoteServiceCallback aVar;
        long elapsedRealtime2;
        StringBuilder sb;
        String m357b;
        Activity activity2;
        Activity activity3;
        Intent intent = new Intent();
        intent.setPackage(str2);
        intent.setAction("com.eg.android.AlipayGphone.IAlixPay");
        String m439c = C1383h.m439c(this.f1293a, str2);
        long elapsedRealtime3 = SystemClock.elapsedRealtime();
        StringBuilder sb2 = new StringBuilder();
        sb2.append("");
        sb2.append(elapsedRealtime3);
        sb2.append("|");
        sb2.append(str != null ? str.length() : 0);
        C1353c.m367h(c1373a, "biz", "PgBindStarting", sb2.toString());
        C1353c.m360a(this.f1293a, c1373a, str, c1373a.f1250d);
        try {
            try {
                if (C1356a.m376d().f1204i) {
                    C1353c.m367h(c1373a, "biz", "stSrv", "skipped");
                } else {
                    ComponentName startService = this.f1293a.getApplication().startService(intent);
                    C1353c.m367h(c1373a, "biz", "stSrv", startService != null ? startService.getPackageName() : "null");
                }
            } catch (Throwable th) {
                C1353c.m363d(c1373a, "biz", "ClientBindServiceFailed", th);
                return new Pair<>("failed", Boolean.TRUE);
            }
        } catch (Throwable th2) {
            C1353c.m363d(c1373a, "biz", "TryStartServiceEx", th2);
        }
        if (C1356a.m376d().f1207l) {
            i2 = 65;
            C1353c.m367h(c1373a, "biz", "bindFlg", "imp");
        } else {
            i2 = 1;
        }
        IRemoteServiceCallback iRemoteServiceCallback = null;
        b bVar2 = new b(null);
        if (!this.f1293a.getApplicationContext().bindService(intent, bVar2, i2)) {
            throw new Throwable("bindService fail");
        }
        synchronized (this.f1295c) {
            if (this.f1294b == null) {
                try {
                    this.f1295c.wait(C1356a.m376d().m377a());
                } catch (InterruptedException e2) {
                    C1353c.m363d(c1373a, "biz", "BindWaitTimeoutEx", e2);
                }
            }
        }
        IAlixPay iAlixPay = this.f1294b;
        try {
            if (iAlixPay == null) {
                C1353c.m362c(c1373a, "biz", "ClientBindFailed", m439c + "|" + C1383h.m439c(this.f1293a, str2));
                Pair<String, Boolean> pair = new Pair<>("failed", Boolean.TRUE);
                try {
                    this.f1293a.getApplicationContext().unbindService(bVar2);
                } catch (Throwable th3) {
                    C4195m.m4816l(th3);
                }
                StringBuilder m586H = C1499a.m586H("");
                m586H.append(SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgBindEnd", m586H.toString());
                C1353c.m360a(this.f1293a, c1373a, str, c1373a.f1250d);
                this.f1294b = null;
                if (this.f1296d && (activity3 = this.f1293a) != null) {
                    activity3.setRequestedOrientation(0);
                    this.f1296d = false;
                }
                return pair;
            }
            try {
                elapsedRealtime = SystemClock.elapsedRealtime();
                C1353c.m367h(c1373a, "biz", "PgBinded", "" + elapsedRealtime);
                c cVar = this.f1297e;
                if (cVar != null) {
                    cVar.mo347a();
                }
                if (this.f1293a.getRequestedOrientation() == 0) {
                    this.f1293a.setRequestedOrientation(1);
                    this.f1296d = true;
                }
                try {
                    i3 = iAlixPay.getVersion();
                } catch (Throwable th4) {
                    C4195m.m4816l(th4);
                    i3 = 0;
                }
                aVar = new a(null);
                try {
                    if (i3 >= 3) {
                        iAlixPay.registerCallback03(aVar, str, null);
                    } else {
                        iAlixPay.registerCallback(aVar);
                    }
                    elapsedRealtime2 = SystemClock.elapsedRealtime();
                    sb = new StringBuilder();
                } catch (Throwable th5) {
                    th = th5;
                    bVar = bVar2;
                }
            } catch (Throwable th6) {
                th = th6;
                bVar = bVar2;
                iRemoteServiceCallback = null;
            }
            try {
                sb.append("");
                sb.append(elapsedRealtime2);
                C1353c.m367h(c1373a, "biz", "PgBindPay", sb.toString());
                if (i3 >= 3) {
                    iAlixPay.r03("biz", "bind_pay", null);
                }
                try {
                    if (i3 >= 2) {
                        HashMap<String, String> m409d = C1373a.m409d(c1373a);
                        m409d.put("ts_bind", String.valueOf(elapsedRealtime3));
                        m409d.put("ts_bend", String.valueOf(elapsedRealtime));
                        m409d.put("ts_pay", String.valueOf(elapsedRealtime2));
                        m357b = iAlixPay.pay02(str, m409d);
                    } else {
                        m357b = iAlixPay.Pay(str);
                    }
                } catch (Throwable th7) {
                    C1353c.m363d(c1373a, "biz", "ClientBindException", th7);
                    m357b = C1349f.m357b();
                }
                String str3 = m357b;
                try {
                    iAlixPay.unregisterCallback(aVar);
                } catch (Throwable th8) {
                    C4195m.m4816l(th8);
                }
                try {
                    this.f1293a.getApplicationContext().unbindService(bVar2);
                } catch (Throwable th9) {
                    C4195m.m4816l(th9);
                }
                StringBuilder m586H2 = C1499a.m586H("");
                m586H2.append(SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgBindEnd", m586H2.toString());
                C1353c.m360a(this.f1293a, c1373a, str, c1373a.f1250d);
                this.f1294b = null;
                if (this.f1296d && (activity2 = this.f1293a) != null) {
                    activity2.setRequestedOrientation(0);
                    this.f1296d = false;
                }
                return new Pair<>(str3, Boolean.FALSE);
            } catch (Throwable th10) {
                th = th10;
                bVar = bVar2;
                iRemoteServiceCallback = aVar;
                try {
                    C1353c.m364e(c1373a, "biz", "ClientBindFailed", th, "in_bind");
                    Pair<String, Boolean> pair2 = new Pair<>("failed", Boolean.TRUE);
                    if (iRemoteServiceCallback != null) {
                        try {
                            iAlixPay.unregisterCallback(iRemoteServiceCallback);
                        } catch (Throwable th11) {
                            C4195m.m4816l(th11);
                        }
                    }
                    try {
                        this.f1293a.getApplicationContext().unbindService(bVar);
                    } catch (Throwable th12) {
                        C4195m.m4816l(th12);
                    }
                    StringBuilder m586H3 = C1499a.m586H("");
                    m586H3.append(SystemClock.elapsedRealtime());
                    C1353c.m367h(c1373a, "biz", "PgBindEnd", m586H3.toString());
                    C1353c.m360a(this.f1293a, c1373a, str, c1373a.f1250d);
                    this.f1294b = null;
                    if (this.f1296d && (activity = this.f1293a) != null) {
                        activity.setRequestedOrientation(0);
                        this.f1296d = false;
                    }
                    return pair2;
                } finally {
                }
            }
        } catch (Throwable th13) {
            th = th13;
            bVar = bVar2;
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(21:16|(18:21|22|23|24|(1:26)(1:173)|27|28|(4:33|34|35|36)|170|(1:44)(1:169)|45|46|47|(1:49)(3:158|(2:160|(2:163|164)(1:162))|166)|50|(1:52)(4:145|146|147|(2:153|154))|53|(2:55|(2:57|58)(2:59|(2:142|143)(2:63|(3:71|(4:73|74|75|(3:77|78|(9:80|(1:84)|85|86|87|88|(1:(2:90|(4:93|94|(1:96)(1:129)|97)(1:92))(2:130|131))|98|(2:100|(10:102|103|104|105|106|107|108|(1:110)|111|(1:113)(1:118))(2:125|126))(2:127|128)))(2:138|(0)))|141)(2:69|70))))(1:144))|178|179|22|23|24|(0)(0)|27|28|(5:30|33|34|35|36)|170|(0)(0)|45|46|47|(0)(0)|50|(0)(0)|53|(0)(0)) */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0101, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0102, code lost:
    
        p403d.p404a.p405a.p407b.p408a.C4195m.m4816l(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x00aa, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x00b2, code lost:
    
        p005b.p085c.p088b.p089a.p090h.C1353c.m363d(r17.f1298f, "biz", "CheckClientSignEx", r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x00ac, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x00b1, code lost:
    
        r10 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x0075, code lost:
    
        r8 = "com.eg.android.AlipayGphone";
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x004f, code lost:
    
        if (android.text.TextUtils.equals(r10, r11[1]) != false) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00bb, code lost:
    
        r9 = r10.versionCode;
     */
    /* JADX WARN: Removed duplicated region for block: B:144:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0056 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:158:0x00f0 A[Catch: all -> 0x0101, TryCatch #0 {all -> 0x0101, blocks: (B:47:0x00db, B:158:0x00f0, B:160:0x00f4), top: B:46:0x00db }] */
    /* JADX WARN: Removed duplicated region for block: B:169:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0057 A[Catch: all -> 0x00af, TRY_ENTER, TryCatch #7 {all -> 0x00af, blocks: (B:3:0x000f, B:5:0x0028, B:7:0x0030, B:10:0x0038, B:16:0x0057, B:18:0x005b, B:21:0x0064), top: B:2:0x000f }] */
    /* JADX WARN: Removed duplicated region for block: B:173:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0171  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01d7  */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String m428b(java.lang.String r18) {
        /*
            Method dump skipped, instructions count: 1049
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p100j.C1380e.m428b(java.lang.String):java.lang.String");
    }
}
