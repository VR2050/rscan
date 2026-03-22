package com.blankj.utilcode.util;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import androidx.annotation.RequiresPermission;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import p005b.p139f.p140a.p142b.C1540j;
import p005b.p139f.p140a.p142b.C1550t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class NetworkUtils {

    public static final class NetworkChangedReceiver extends BroadcastReceiver {

        /* renamed from: a */
        public static final /* synthetic */ int f8807a = 0;

        /* renamed from: b */
        public EnumC3213a f8808b;

        /* renamed from: c */
        public Set<InterfaceC3214b> f8809c = new HashSet();

        /* renamed from: com.blankj.utilcode.util.NetworkUtils$NetworkChangedReceiver$a */
        public class RunnableC3209a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ InterfaceC3214b f8810c;

            public RunnableC3209a(InterfaceC3214b interfaceC3214b) {
                this.f8810c = interfaceC3214b;
            }

            @Override // java.lang.Runnable
            @RequiresPermission("android.permission.ACCESS_NETWORK_STATE")
            public void run() {
                int size = NetworkChangedReceiver.this.f8809c.size();
                NetworkChangedReceiver.this.f8809c.add(this.f8810c);
                if (size == 0 && NetworkChangedReceiver.this.f8809c.size() == 1) {
                    NetworkChangedReceiver.this.f8808b = NetworkUtils.m3880a();
                    C4195m.m4792Y().registerReceiver(C3212d.f8815a, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
                }
            }
        }

        /* renamed from: com.blankj.utilcode.util.NetworkUtils$NetworkChangedReceiver$b */
        public class RunnableC3210b implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ InterfaceC3214b f8812c;

            public RunnableC3210b(InterfaceC3214b interfaceC3214b) {
                this.f8812c = interfaceC3214b;
            }

            @Override // java.lang.Runnable
            public void run() {
                int size = NetworkChangedReceiver.this.f8809c.size();
                NetworkChangedReceiver.this.f8809c.remove(this.f8812c);
                if (size == 1 && NetworkChangedReceiver.this.f8809c.size() == 0) {
                    C4195m.m4792Y().unregisterReceiver(C3212d.f8815a);
                }
            }
        }

        /* renamed from: com.blankj.utilcode.util.NetworkUtils$NetworkChangedReceiver$c */
        public class RunnableC3211c implements Runnable {
            public RunnableC3211c() {
            }

            @Override // java.lang.Runnable
            @RequiresPermission("android.permission.ACCESS_NETWORK_STATE")
            public void run() {
                EnumC3213a m3880a = NetworkUtils.m3880a();
                NetworkChangedReceiver networkChangedReceiver = NetworkChangedReceiver.this;
                if (networkChangedReceiver.f8808b == m3880a) {
                    return;
                }
                networkChangedReceiver.f8808b = m3880a;
                if (m3880a == EnumC3213a.NETWORK_NO) {
                    Iterator<InterfaceC3214b> it = networkChangedReceiver.f8809c.iterator();
                    while (it.hasNext()) {
                        it.next().m3882b();
                    }
                } else {
                    Iterator<InterfaceC3214b> it2 = networkChangedReceiver.f8809c.iterator();
                    while (it2.hasNext()) {
                        it2.next().m3881a(m3880a);
                    }
                }
            }
        }

        /* renamed from: com.blankj.utilcode.util.NetworkUtils$NetworkChangedReceiver$d */
        public static class C3212d {

            /* renamed from: a */
            public static final NetworkChangedReceiver f8815a = new NetworkChangedReceiver();
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if ("android.net.conn.CONNECTIVITY_CHANGE".equals(intent.getAction())) {
                C1540j.f1772a.postDelayed(new RunnableC3211c(), 1000L);
            }
        }

        @RequiresPermission("android.permission.ACCESS_NETWORK_STATE")
        public void registerListener(InterfaceC3214b interfaceC3214b) {
            if (interfaceC3214b == null) {
                return;
            }
            C1550t.m731h(new RunnableC3209a(interfaceC3214b));
        }

        public void unregisterListener(InterfaceC3214b interfaceC3214b) {
            if (interfaceC3214b == null) {
                return;
            }
            C1550t.m731h(new RunnableC3210b(interfaceC3214b));
        }
    }

    /* renamed from: com.blankj.utilcode.util.NetworkUtils$a */
    public enum EnumC3213a {
        NETWORK_ETHERNET,
        NETWORK_WIFI,
        NETWORK_5G,
        NETWORK_4G,
        NETWORK_3G,
        NETWORK_2G,
        NETWORK_UNKNOWN,
        NETWORK_NO
    }

    /* renamed from: com.blankj.utilcode.util.NetworkUtils$b */
    public interface InterfaceC3214b {
        /* renamed from: a */
        void m3881a(EnumC3213a enumC3213a);

        /* renamed from: b */
        void m3882b();
    }

    static {
        new CopyOnWriteArraySet();
    }

    @RequiresPermission("android.permission.ACCESS_NETWORK_STATE")
    /* renamed from: a */
    public static EnumC3213a m3880a() {
        NetworkInfo networkInfo;
        NetworkInfo.State state;
        EnumC3213a enumC3213a = EnumC3213a.NETWORK_3G;
        EnumC3213a enumC3213a2 = EnumC3213a.NETWORK_UNKNOWN;
        ConnectivityManager connectivityManager = (ConnectivityManager) C4195m.m4792Y().getSystemService("connectivity");
        boolean z = false;
        if (connectivityManager != null && (networkInfo = connectivityManager.getNetworkInfo(9)) != null && (state = networkInfo.getState()) != null && (state == NetworkInfo.State.CONNECTED || state == NetworkInfo.State.CONNECTING)) {
            z = true;
        }
        if (z) {
            return EnumC3213a.NETWORK_ETHERNET;
        }
        ConnectivityManager connectivityManager2 = (ConnectivityManager) C4195m.m4792Y().getSystemService("connectivity");
        NetworkInfo activeNetworkInfo = connectivityManager2 == null ? null : connectivityManager2.getActiveNetworkInfo();
        if (activeNetworkInfo == null || !activeNetworkInfo.isAvailable()) {
            return EnumC3213a.NETWORK_NO;
        }
        if (activeNetworkInfo.getType() == 1) {
            return EnumC3213a.NETWORK_WIFI;
        }
        if (activeNetworkInfo.getType() != 0) {
            return enumC3213a2;
        }
        switch (activeNetworkInfo.getSubtype()) {
            case 1:
            case 2:
            case 4:
            case 7:
            case 11:
            case 16:
                return EnumC3213a.NETWORK_2G;
            case 3:
            case 5:
            case 6:
            case 8:
            case 9:
            case 10:
            case 12:
            case 14:
            case 15:
            case 17:
                return enumC3213a;
            case 13:
            case 18:
                return EnumC3213a.NETWORK_4G;
            case 19:
            default:
                String subtypeName = activeNetworkInfo.getSubtypeName();
                return (subtypeName.equalsIgnoreCase("TD-SCDMA") || subtypeName.equalsIgnoreCase("WCDMA") || subtypeName.equalsIgnoreCase("CDMA2000")) ? enumC3213a : enumC3213a2;
            case 20:
                return EnumC3213a.NETWORK_5G;
        }
    }

    @RequiresPermission("android.permission.ACCESS_NETWORK_STATE")
    public static void registerNetworkStatusChangedListener(InterfaceC3214b interfaceC3214b) {
        int i2 = NetworkChangedReceiver.f8807a;
        NetworkChangedReceiver.C3212d.f8815a.registerListener(interfaceC3214b);
    }

    public static void unregisterNetworkStatusChangedListener(InterfaceC3214b interfaceC3214b) {
        int i2 = NetworkChangedReceiver.f8807a;
        NetworkChangedReceiver.C3212d.f8815a.unregisterListener(interfaceC3214b);
    }
}
