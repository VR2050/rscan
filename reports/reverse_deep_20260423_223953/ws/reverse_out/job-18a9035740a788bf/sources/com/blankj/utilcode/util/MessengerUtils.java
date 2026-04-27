package com.blankj.utilcode.util;

import android.app.ActivityManager;
import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes.dex */
public class MessengerUtils {
    private static final String KEY_STRING = "MESSENGER_UTILS";
    private static final int WHAT_SEND = 2;
    private static final int WHAT_SUBSCRIBE = 0;
    private static final int WHAT_UNSUBSCRIBE = 1;
    private static Client sLocalClient;
    private static ConcurrentHashMap<String, MessageCallback> subscribers = new ConcurrentHashMap<>();
    private static Map<String, Client> sClientMap = new HashMap();

    public interface MessageCallback {
        void messageCall(Bundle bundle);
    }

    public static void register() {
        if (isMainProcess()) {
            if (isServiceRunning(ServerService.class.getName())) {
                Log.i("MessengerUtils", "Server service is running.");
                return;
            } else {
                Intent intent = new Intent(Utils.getApp(), (Class<?>) ServerService.class);
                Utils.getApp().startService(intent);
                return;
            }
        }
        if (sLocalClient == null) {
            Client client = new Client(null);
            if (client.bind()) {
                sLocalClient = client;
                return;
            } else {
                Log.e("MessengerUtils", "Bind service failed.");
                return;
            }
        }
        Log.i("MessengerUtils", "The client have been bind.");
    }

    public static void unregister() {
        if (isMainProcess()) {
            if (!isServiceRunning(ServerService.class.getName())) {
                Log.i("MessengerUtils", "Server service isn't running.");
                return;
            } else {
                Intent intent = new Intent(Utils.getApp(), (Class<?>) ServerService.class);
                Utils.getApp().stopService(intent);
            }
        }
        Client client = sLocalClient;
        if (client != null) {
            client.unbind();
        }
    }

    public static void register(String pkgName) {
        if (sClientMap.containsKey(pkgName)) {
            Log.i("MessengerUtils", "register: client registered: " + pkgName);
            return;
        }
        Client client = new Client(pkgName);
        if (client.bind()) {
            sClientMap.put(pkgName, client);
            return;
        }
        Log.e("MessengerUtils", "register: client bind failed: " + pkgName);
    }

    public static void unregister(String pkgName) {
        if (sClientMap.containsKey(pkgName)) {
            Client client = sClientMap.get(pkgName);
            client.unbind();
        } else {
            Log.i("MessengerUtils", "unregister: client didn't register: " + pkgName);
        }
    }

    public static void subscribe(String key, MessageCallback callback) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (callback == null) {
            throw new NullPointerException("Argument 'callback' of type MessageCallback (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        subscribers.put(key, callback);
    }

    public static void unsubscribe(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        subscribers.remove(key);
    }

    public static void post(String key, Bundle data) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (data == null) {
            throw new NullPointerException("Argument 'data' of type Bundle (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        data.putString(KEY_STRING, key);
        Client client = sLocalClient;
        if (client != null) {
            client.sendMsg2Server(data);
        } else {
            Intent intent = new Intent(Utils.getApp(), (Class<?>) ServerService.class);
            intent.putExtras(data);
            Utils.getApp().startService(intent);
        }
        for (Client client2 : sClientMap.values()) {
            client2.sendMsg2Server(data);
        }
    }

    private static boolean isMainProcess() {
        return Utils.getApp().getPackageName().equals(Utils.getCurrentProcessName());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean isAppInstalled(String pkgName) {
        if (pkgName == null) {
            throw new NullPointerException("Argument 'pkgName' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager packageManager = Utils.getApp().getPackageManager();
        try {
            return packageManager.getApplicationInfo(pkgName, 0) != null;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static boolean isServiceRunning(String className) {
        ActivityManager am = (ActivityManager) Utils.getApp().getSystemService("activity");
        List<ActivityManager.RunningServiceInfo> info = am.getRunningServices(Integer.MAX_VALUE);
        if (info == null || info.size() == 0) {
            return false;
        }
        for (ActivityManager.RunningServiceInfo aInfo : info) {
            if (className.equals(aInfo.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean isAppRunning(String pkgName) {
        if (pkgName == null) {
            throw new NullPointerException("Argument 'pkgName' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager packageManager = Utils.getApp().getPackageManager();
        try {
            ApplicationInfo ai = packageManager.getApplicationInfo(pkgName, 0);
            if (ai == null) {
                return false;
            }
            int uid = ai.uid;
            ActivityManager am = (ActivityManager) Utils.getApp().getSystemService("activity");
            if (am != null) {
                List<ActivityManager.RunningTaskInfo> taskInfo = am.getRunningTasks(Integer.MAX_VALUE);
                if (taskInfo != null && taskInfo.size() > 0) {
                    for (ActivityManager.RunningTaskInfo aInfo : taskInfo) {
                        if (pkgName.equals(aInfo.baseActivity.getPackageName())) {
                            return true;
                        }
                    }
                }
                List<ActivityManager.RunningServiceInfo> serviceInfo = am.getRunningServices(Integer.MAX_VALUE);
                if (serviceInfo != null && serviceInfo.size() > 0) {
                    for (ActivityManager.RunningServiceInfo aInfo2 : serviceInfo) {
                        if (uid == aInfo2.uid) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }

    static class Client {
        String mPkgName;
        Messenger mServer;
        LinkedList<Bundle> mCached = new LinkedList<>();
        Handler mReceiveServeMsgHandler = new Handler() { // from class: com.blankj.utilcode.util.MessengerUtils.Client.1
            @Override // android.os.Handler
            public void handleMessage(Message msg) {
                String key;
                MessageCallback callback;
                Bundle data = msg.getData();
                if (data != null && (key = data.getString(MessengerUtils.KEY_STRING)) != null && (callback = (MessageCallback) MessengerUtils.subscribers.get(key)) != null) {
                    callback.messageCall(data);
                }
            }
        };
        Messenger mClient = new Messenger(this.mReceiveServeMsgHandler);
        ServiceConnection mConn = new ServiceConnection() { // from class: com.blankj.utilcode.util.MessengerUtils.Client.2
            @Override // android.content.ServiceConnection
            public void onServiceConnected(ComponentName name, IBinder service) {
                Log.d("MessengerUtils", "client service connected " + name);
                Client.this.mServer = new Messenger(service);
                int key = Utils.getCurrentProcessName().hashCode();
                Message msg = Message.obtain(Client.this.mReceiveServeMsgHandler, 0, key, 0);
                msg.replyTo = Client.this.mClient;
                try {
                    Client.this.mServer.send(msg);
                } catch (RemoteException e) {
                    Log.e("MessengerUtils", "onServiceConnected: ", e);
                }
                Client.this.sendCachedMsg2Server();
            }

            @Override // android.content.ServiceConnection
            public void onServiceDisconnected(ComponentName name) {
                Log.w("MessengerUtils", "client service disconnected:" + name);
                Client.this.mServer = null;
                if (!Client.this.bind()) {
                    Log.e("MessengerUtils", "client service rebind failed: " + name);
                }
            }
        };

        Client(String pkgName) {
            this.mPkgName = pkgName;
        }

        boolean bind() {
            if (!TextUtils.isEmpty(this.mPkgName)) {
                if (MessengerUtils.isAppInstalled(this.mPkgName)) {
                    if (MessengerUtils.isAppRunning(this.mPkgName)) {
                        Intent intent = new Intent(this.mPkgName + ".messenger");
                        intent.setPackage(this.mPkgName);
                        return Utils.getApp().bindService(intent, this.mConn, 1);
                    }
                    Log.e("MessengerUtils", "bind: the app is not running -> " + this.mPkgName);
                    return false;
                }
                Log.e("MessengerUtils", "bind: the app is not installed -> " + this.mPkgName);
                return false;
            }
            return Utils.getApp().bindService(new Intent(Utils.getApp(), (Class<?>) ServerService.class), this.mConn, 1);
        }

        void unbind() {
            Message msg = Message.obtain(this.mReceiveServeMsgHandler, 1);
            msg.replyTo = this.mClient;
            try {
                this.mServer.send(msg);
            } catch (RemoteException e) {
                Log.e("MessengerUtils", "unbind: ", e);
            }
            try {
                Utils.getApp().unbindService(this.mConn);
            } catch (Exception e2) {
            }
        }

        void sendMsg2Server(Bundle bundle) {
            if (this.mServer == null) {
                this.mCached.addFirst(bundle);
                Log.i("MessengerUtils", "save the bundle " + bundle);
                return;
            }
            sendCachedMsg2Server();
            if (!send2Server(bundle)) {
                this.mCached.addFirst(bundle);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void sendCachedMsg2Server() {
            if (this.mCached.isEmpty()) {
                return;
            }
            for (int i = this.mCached.size() - 1; i >= 0; i--) {
                if (send2Server(this.mCached.get(i))) {
                    this.mCached.remove(i);
                }
            }
        }

        private boolean send2Server(Bundle bundle) {
            Message msg = Message.obtain(this.mReceiveServeMsgHandler, 2);
            msg.setData(bundle);
            msg.replyTo = this.mClient;
            try {
                this.mServer.send(msg);
                return true;
            } catch (RemoteException e) {
                Log.e("MessengerUtils", "send2Server: ", e);
                return false;
            }
        }
    }

    public static class ServerService extends Service {
        private final ConcurrentHashMap<Integer, Messenger> mClientMap = new ConcurrentHashMap<>();
        private final Handler mReceiveClientMsgHandler = new Handler() { // from class: com.blankj.utilcode.util.MessengerUtils.ServerService.1
            @Override // android.os.Handler
            public void handleMessage(Message msg) {
                int i = msg.what;
                if (i == 0) {
                    ServerService.this.mClientMap.put(Integer.valueOf(msg.arg1), msg.replyTo);
                    return;
                }
                if (i == 1) {
                    ServerService.this.mClientMap.remove(Integer.valueOf(msg.arg1));
                } else if (i == 2) {
                    ServerService.this.sendMsg2Client(msg);
                    ServerService.this.consumeServerProcessCallback(msg);
                } else {
                    super.handleMessage(msg);
                }
            }
        };
        private final Messenger messenger = new Messenger(this.mReceiveClientMsgHandler);

        @Override // android.app.Service
        public IBinder onBind(Intent intent) {
            return this.messenger.getBinder();
        }

        @Override // android.app.Service
        public int onStartCommand(Intent intent, int flags, int startId) {
            Bundle extras;
            if (intent != null && (extras = intent.getExtras()) != null) {
                Message msg = Message.obtain(this.mReceiveClientMsgHandler, 2);
                msg.replyTo = this.messenger;
                msg.setData(extras);
                sendMsg2Client(msg);
                consumeServerProcessCallback(msg);
            }
            return 2;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void sendMsg2Client(Message msg) {
            for (Messenger client : this.mClientMap.values()) {
                if (client != null) {
                    try {
                        client.send(msg);
                    } catch (RemoteException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void consumeServerProcessCallback(Message msg) {
            String key;
            MessageCallback callback;
            Bundle data = msg.getData();
            if (data != null && (key = data.getString(MessengerUtils.KEY_STRING)) != null && (callback = (MessageCallback) MessengerUtils.subscribers.get(key)) != null) {
                callback.messageCall(data);
            }
        }
    }
}
