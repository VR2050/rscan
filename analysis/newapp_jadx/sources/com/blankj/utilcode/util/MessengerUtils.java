package com.blankj.utilcode.util;

import android.annotation.SuppressLint;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import p005b.p139f.p140a.p142b.C1536f;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class MessengerUtils {

    /* renamed from: a */
    public static ConcurrentHashMap<String, InterfaceC3208a> f8801a = new ConcurrentHashMap<>();

    public static class ServerService extends Service {

        /* renamed from: c */
        public static final /* synthetic */ int f8802c = 0;

        /* renamed from: e */
        public final ConcurrentHashMap<Integer, Messenger> f8803e = new ConcurrentHashMap<>();

        /* renamed from: f */
        @SuppressLint({"HandlerLeak"})
        public final Handler f8804f;

        /* renamed from: g */
        public final Messenger f8805g;

        /* renamed from: com.blankj.utilcode.util.MessengerUtils$ServerService$a */
        public class HandlerC3207a extends Handler {
            public HandlerC3207a() {
            }

            @Override // android.os.Handler
            public void handleMessage(Message message) {
                int i2 = message.what;
                if (i2 == 0) {
                    ServerService.this.f8803e.put(Integer.valueOf(message.arg1), message.replyTo);
                    return;
                }
                if (i2 == 1) {
                    ServerService.this.f8803e.remove(Integer.valueOf(message.arg1));
                    return;
                }
                if (i2 != 2) {
                    super.handleMessage(message);
                    return;
                }
                ServerService serverService = ServerService.this;
                int i3 = ServerService.f8802c;
                serverService.m3878b(message);
                ServerService.this.m3877a(message);
            }
        }

        public ServerService() {
            HandlerC3207a handlerC3207a = new HandlerC3207a();
            this.f8804f = handlerC3207a;
            this.f8805g = new Messenger(handlerC3207a);
        }

        /* renamed from: a */
        public final void m3877a(Message message) {
            String string;
            InterfaceC3208a interfaceC3208a;
            Bundle data = message.getData();
            if (data == null || (string = data.getString("MESSENGER_UTILS")) == null || (interfaceC3208a = MessengerUtils.f8801a.get(string)) == null) {
                return;
            }
            interfaceC3208a.m3879a(data);
        }

        /* renamed from: b */
        public final void m3878b(Message message) {
            Message obtain = Message.obtain(message);
            for (Messenger messenger : this.f8803e.values()) {
                if (messenger != null) {
                    try {
                        messenger.send(Message.obtain(obtain));
                    } catch (RemoteException e2) {
                        e2.printStackTrace();
                    }
                }
            }
            obtain.recycle();
        }

        @Override // android.app.Service
        @Nullable
        public IBinder onBind(Intent intent) {
            return this.f8805g.getBinder();
        }

        @Override // android.app.Service
        public int onStartCommand(Intent intent, int i2, int i3) {
            Bundle extras;
            int i4 = Build.VERSION.SDK_INT;
            if (i4 >= 26) {
                C1536f c1536f = C1536f.f1732a;
                if (i4 >= 26) {
                    ((NotificationManager) C4195m.m4792Y().getSystemService("notification")).createNotificationChannel(c1536f.f1733b);
                }
                NotificationCompat.Builder builder = new NotificationCompat.Builder(C4195m.m4792Y());
                if (i4 >= 26) {
                    builder.setChannelId(c1536f.f1733b.getId());
                }
                startForeground(1, builder.build());
            }
            if (intent != null && (extras = intent.getExtras()) != null) {
                Message obtain = Message.obtain(this.f8804f, 2);
                obtain.replyTo = this.f8805g;
                obtain.setData(extras);
                m3878b(obtain);
                m3877a(obtain);
            }
            return 2;
        }
    }

    /* renamed from: com.blankj.utilcode.util.MessengerUtils$a */
    public interface InterfaceC3208a {
        /* renamed from: a */
        void m3879a(Bundle bundle);
    }

    static {
        new HashMap();
    }
}
