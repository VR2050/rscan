package p005b.p143g.p144a.p163n;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;
import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.p163n.InterfaceC1749c;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.n.e */
/* loaded from: classes.dex */
public final class C1751e implements InterfaceC1749c {

    /* renamed from: c */
    public final Context f2610c;

    /* renamed from: e */
    public final InterfaceC1749c.a f2611e;

    /* renamed from: f */
    public boolean f2612f;

    /* renamed from: g */
    public boolean f2613g;

    /* renamed from: h */
    public final BroadcastReceiver f2614h = new a();

    /* renamed from: b.g.a.n.e$a */
    public class a extends BroadcastReceiver {
        public a() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(@NonNull Context context, Intent intent) {
            C1751e c1751e = C1751e.this;
            boolean z = c1751e.f2612f;
            c1751e.f2612f = c1751e.m1045a(context);
            if (z != C1751e.this.f2612f) {
                if (Log.isLoggable("ConnectivityMonitor", 3)) {
                    boolean z2 = C1751e.this.f2612f;
                }
                C1751e c1751e2 = C1751e.this;
                InterfaceC1749c.a aVar = c1751e2.f2611e;
                boolean z3 = c1751e2.f2612f;
                ComponentCallbacks2C1559i.c cVar = (ComponentCallbacks2C1559i.c) aVar;
                Objects.requireNonNull(cVar);
                if (z3) {
                    synchronized (ComponentCallbacks2C1559i.this) {
                        C1760n c1760n = cVar.f1885a;
                        Iterator it = ((ArrayList) C1807i.m1148e(c1760n.f2632a)).iterator();
                        while (it.hasNext()) {
                            InterfaceC1775b interfaceC1775b = (InterfaceC1775b) it.next();
                            if (!interfaceC1775b.mo1102d() && !interfaceC1775b.mo1100b()) {
                                interfaceC1775b.clear();
                                if (c1760n.f2634c) {
                                    c1760n.f2633b.add(interfaceC1775b);
                                } else {
                                    interfaceC1775b.mo1101c();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public C1751e(@NonNull Context context, @NonNull InterfaceC1749c.a aVar) {
        this.f2610c = context.getApplicationContext();
        this.f2611e = aVar;
    }

    @SuppressLint({"MissingPermission"})
    /* renamed from: a */
    public boolean m1045a(@NonNull Context context) {
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        Objects.requireNonNull(connectivityManager, "Argument must not be null");
        try {
            NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
            return activeNetworkInfo != null && activeNetworkInfo.isConnected();
        } catch (RuntimeException unused) {
            Log.isLoggable("ConnectivityMonitor", 5);
            return true;
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onDestroy() {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
        if (this.f2613g) {
            return;
        }
        this.f2612f = m1045a(this.f2610c);
        try {
            this.f2610c.registerReceiver(this.f2614h, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
            this.f2613g = true;
        } catch (SecurityException unused) {
            Log.isLoggable("ConnectivityMonitor", 5);
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
        if (this.f2613g) {
            this.f2610c.unregisterReceiver(this.f2614h);
            this.f2613g = false;
        }
    }
}
