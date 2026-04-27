package com.google.firebase.iid;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import android.util.SparseArray;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.stats.ConnectionTracker;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.TimeUnit;

/* JADX INFO: compiled from: com.google.firebase:firebase-iid@@20.0.2 */
/* JADX INFO: loaded from: classes.dex */
final class zzw implements ServiceConnection {
    int zza;
    final Messenger zzb;
    zzaf zzc;
    final Queue<zzah<?>> zzd;
    final SparseArray<zzah<?>> zze;
    final /* synthetic */ zzv zzf;

    private zzw(zzv zzvVar) {
        this.zzf = zzvVar;
        this.zza = 0;
        this.zzb = new Messenger(new com.google.android.gms.internal.firebase_messaging.zze(Looper.getMainLooper(), new Handler.Callback(this) { // from class: com.google.firebase.iid.zzz
            private final zzw zza;

            {
                this.zza = this;
            }

            @Override // android.os.Handler.Callback
            public final boolean handleMessage(Message message) {
                return this.zza.zza(message);
            }
        }));
        this.zzd = new ArrayDeque();
        this.zze = new SparseArray<>();
    }

    final synchronized boolean zza(zzah<?> zzahVar) {
        int i = this.zza;
        if (i == 0) {
            this.zzd.add(zzahVar);
            Preconditions.checkState(this.zza == 0);
            if (Log.isLoggable("MessengerIpcClient", 2)) {
                Log.v("MessengerIpcClient", "Starting bind to GmsCore");
            }
            this.zza = 1;
            Intent intent = new Intent("com.google.android.c2dm.intent.REGISTER");
            intent.setPackage("com.google.android.gms");
            if (!ConnectionTracker.getInstance().bindService(this.zzf.zzb, intent, this, 1)) {
                zza(0, "Unable to bind to service");
            } else {
                this.zzf.zzc.schedule(new Runnable(this) { // from class: com.google.firebase.iid.zzy
                    private final zzw zza;

                    {
                        this.zza = this;
                    }

                    @Override // java.lang.Runnable
                    public final void run() {
                        this.zza.zzc();
                    }
                }, 30L, TimeUnit.SECONDS);
            }
            return true;
        }
        if (i == 1) {
            this.zzd.add(zzahVar);
            return true;
        }
        if (i == 2) {
            this.zzd.add(zzahVar);
            zza();
            return true;
        }
        if (i != 3 && i != 4) {
            int i2 = this.zza;
            StringBuilder sb = new StringBuilder(26);
            sb.append("Unknown state: ");
            sb.append(i2);
            throw new IllegalStateException(sb.toString());
        }
        return false;
    }

    final boolean zza(Message message) {
        int i = message.arg1;
        if (Log.isLoggable("MessengerIpcClient", 3)) {
            StringBuilder sb = new StringBuilder(41);
            sb.append("Received response to request: ");
            sb.append(i);
            Log.d("MessengerIpcClient", sb.toString());
        }
        synchronized (this) {
            zzah<?> zzahVar = this.zze.get(i);
            if (zzahVar == null) {
                StringBuilder sb2 = new StringBuilder(50);
                sb2.append("Received response for unknown request: ");
                sb2.append(i);
                Log.w("MessengerIpcClient", sb2.toString());
                return true;
            }
            this.zze.remove(i);
            zzb();
            Bundle data = message.getData();
            if (data.getBoolean("unsupported", false)) {
                zzahVar.zza(new zzag(4, "Not supported by GmsCore"));
            } else {
                zzahVar.zza(data);
            }
            return true;
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, final IBinder iBinder) {
        if (Log.isLoggable("MessengerIpcClient", 2)) {
            Log.v("MessengerIpcClient", "Service connected");
        }
        this.zzf.zzc.execute(new Runnable(this, iBinder) { // from class: com.google.firebase.iid.zzab
            private final zzw zza;
            private final IBinder zzb;

            {
                this.zza = this;
                this.zzb = iBinder;
            }

            @Override // java.lang.Runnable
            public final void run() {
                zzw zzwVar = this.zza;
                IBinder iBinder2 = this.zzb;
                synchronized (zzwVar) {
                    try {
                        if (iBinder2 == null) {
                            zzwVar.zza(0, "Null service connection");
                            return;
                        }
                        try {
                            zzwVar.zzc = new zzaf(iBinder2);
                            zzwVar.zza = 2;
                            zzwVar.zza();
                        } catch (RemoteException e) {
                            zzwVar.zza(0, e.getMessage());
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        });
    }

    final void zza() {
        this.zzf.zzc.execute(new Runnable(this) { // from class: com.google.firebase.iid.zzaa
            private final zzw zza;

            {
                this.zza = this;
            }

            @Override // java.lang.Runnable
            public final void run() {
                final zzah<?> zzahVarPoll;
                final zzw zzwVar = this.zza;
                while (true) {
                    synchronized (zzwVar) {
                        if (zzwVar.zza != 2) {
                            return;
                        }
                        if (zzwVar.zzd.isEmpty()) {
                            zzwVar.zzb();
                            return;
                        } else {
                            zzahVarPoll = zzwVar.zzd.poll();
                            zzwVar.zze.put(zzahVarPoll.zza, zzahVarPoll);
                            zzwVar.zzf.zzc.schedule(new Runnable(zzwVar, zzahVarPoll) { // from class: com.google.firebase.iid.zzac
                                private final zzw zza;
                                private final zzah zzb;

                                {
                                    this.zza = zzwVar;
                                    this.zzb = zzahVarPoll;
                                }

                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.zza.zza(this.zzb.zza);
                                }
                            }, 30L, TimeUnit.SECONDS);
                        }
                    }
                    if (Log.isLoggable("MessengerIpcClient", 3)) {
                        String strValueOf = String.valueOf(zzahVarPoll);
                        StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 8);
                        sb.append("Sending ");
                        sb.append(strValueOf);
                        Log.d("MessengerIpcClient", sb.toString());
                    }
                    Context context = zzwVar.zzf.zzb;
                    Messenger messenger = zzwVar.zzb;
                    Message messageObtain = Message.obtain();
                    messageObtain.what = zzahVarPoll.zzc;
                    messageObtain.arg1 = zzahVarPoll.zza;
                    messageObtain.replyTo = messenger;
                    Bundle bundle = new Bundle();
                    bundle.putBoolean("oneWay", zzahVarPoll.zza());
                    bundle.putString("pkg", context.getPackageName());
                    bundle.putBundle("data", zzahVarPoll.zzd);
                    messageObtain.setData(bundle);
                    try {
                        zzwVar.zzc.zza(messageObtain);
                    } catch (RemoteException e) {
                        zzwVar.zza(2, e.getMessage());
                    }
                }
            }
        });
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        if (Log.isLoggable("MessengerIpcClient", 2)) {
            Log.v("MessengerIpcClient", "Service disconnected");
        }
        this.zzf.zzc.execute(new Runnable(this) { // from class: com.google.firebase.iid.zzad
            private final zzw zza;

            {
                this.zza = this;
            }

            @Override // java.lang.Runnable
            public final void run() {
                this.zza.zza(2, "Service disconnected");
            }
        });
    }

    final synchronized void zza(int i, String str) {
        if (Log.isLoggable("MessengerIpcClient", 3)) {
            String strValueOf = String.valueOf(str);
            Log.d("MessengerIpcClient", strValueOf.length() != 0 ? "Disconnected: ".concat(strValueOf) : new String("Disconnected: "));
        }
        int i2 = this.zza;
        if (i2 == 0) {
            throw new IllegalStateException();
        }
        if (i2 != 1 && i2 != 2) {
            if (i2 == 3) {
                this.zza = 4;
                return;
            } else {
                if (i2 == 4) {
                    return;
                }
                int i3 = this.zza;
                StringBuilder sb = new StringBuilder(26);
                sb.append("Unknown state: ");
                sb.append(i3);
                throw new IllegalStateException(sb.toString());
            }
        }
        if (Log.isLoggable("MessengerIpcClient", 2)) {
            Log.v("MessengerIpcClient", "Unbinding service");
        }
        this.zza = 4;
        ConnectionTracker.getInstance().unbindService(this.zzf.zzb, this);
        zzag zzagVar = new zzag(i, str);
        Iterator<zzah<?>> it = this.zzd.iterator();
        while (it.hasNext()) {
            it.next().zza(zzagVar);
        }
        this.zzd.clear();
        for (int i4 = 0; i4 < this.zze.size(); i4++) {
            this.zze.valueAt(i4).zza(zzagVar);
        }
        this.zze.clear();
    }

    final synchronized void zzb() {
        if (this.zza == 2 && this.zzd.isEmpty() && this.zze.size() == 0) {
            if (Log.isLoggable("MessengerIpcClient", 2)) {
                Log.v("MessengerIpcClient", "Finished handling requests, unbinding");
            }
            this.zza = 3;
            ConnectionTracker.getInstance().unbindService(this.zzf.zzb, this);
        }
    }

    final synchronized void zzc() {
        if (this.zza == 1) {
            zza(1, "Timed out while binding");
        }
    }

    final synchronized void zza(int i) {
        zzah<?> zzahVar = this.zze.get(i);
        if (zzahVar != null) {
            StringBuilder sb = new StringBuilder(31);
            sb.append("Timing out request: ");
            sb.append(i);
            Log.w("MessengerIpcClient", sb.toString());
            this.zze.remove(i);
            zzahVar.zza(new zzag(3, "Timed out waiting for response"));
            zzb();
        }
    }
}
