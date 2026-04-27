package com.ding.rtc.monitor;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import com.ding.rtc.monitor.AppFrontBackHelper;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.webrtc.mozi.CodecMonitorHelper;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.NetworkMonitor;
import org.webrtc.mozi.NetworkMonitorAutoDetect;
import org.webrtc.utils.RecvStatsReportCommon;

/* JADX INFO: loaded from: classes.dex */
public class DeviceMonitor implements NetworkMonitor.NetworkObserver {
    public static final int RSSI_UPDATE_PERIOD = 60000;
    private AppFrontBackHelper mAppFrontBackHelper;
    private Context mContext;
    private Handler mMonitorHandler;
    private HandlerThread mMonitorHandlerThread;
    private long mNativeHandle;
    private NetworkMonitor mNetworkMonitor;
    private static boolean needCollectWifiRssiData = false;
    private static boolean isInCall = false;
    private final String TAG = "DeviceMonitor-java";
    private final ReadWriteLock mNativeHandleLock = new ReentrantReadWriteLock();

    /* JADX INFO: Access modifiers changed from: private */
    public native void reportAppBackgroundState(long handle, boolean isBackground);

    private native void reportHardwareInfo(long handle, String osName, String osVersion, String deviceModelName, String manufacturer, String udid, String pkgName, String appName);

    /* JADX INFO: Access modifiers changed from: private */
    public native void reportNetworkRSSI(long handle, int networkRSSI);

    /* JADX INFO: Access modifiers changed from: private */
    public native void reportNetworkType(long handle, int networkType, boolean isInit);

    private DeviceMonitor(long nativeHandle) {
        this.mNativeHandle = nativeHandle;
    }

    public void init() {
        String appName;
        Logging.i("DeviceMonitor-java", CodecMonitorHelper.EVENT_INIT);
        this.mNativeHandleLock.writeLock().lock();
        this.mContext = ContextUtils.getApplicationContext();
        if (this.mMonitorHandler == null) {
            Logging.i("DeviceMonitor-java", "create device monitor thread");
            HandlerThread handlerThread = new HandlerThread("DingRTC_Device_Monitor");
            this.mMonitorHandlerThread = handlerThread;
            handlerThread.start();
            this.mMonitorHandler = new Handler(this.mMonitorHandlerThread.getLooper());
        }
        if (needCollectWifiRssiData) {
            this.mMonitorHandler.postDelayed(new Runnable() { // from class: com.ding.rtc.monitor.DeviceMonitor.1
                @Override // java.lang.Runnable
                public void run() {
                    Logging.i("DeviceMonitor-java", "ReportNetworkRSSI.");
                    DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                    if (DeviceMonitor.isInCall) {
                        int networkRSSI = DeviceMonitor.this.getNetWorkRSSIJNI();
                        if (DeviceMonitor.this.mNativeHandle != 0) {
                            DeviceMonitor deviceMonitor = DeviceMonitor.this;
                            deviceMonitor.reportNetworkRSSI(deviceMonitor.mNativeHandle, networkRSSI);
                        }
                    }
                    if (DeviceMonitor.this.mMonitorHandler != null) {
                        DeviceMonitor.this.mMonitorHandler.postDelayed(this, DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
                    }
                    DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                }
            }, DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
        }
        if (this.mNetworkMonitor == null) {
            NetworkMonitor networkMonitor = NetworkMonitor.getInstance();
            this.mNetworkMonitor = networkMonitor;
            networkMonitor.startMonitoring(this.mContext);
            final NetworkMonitorAutoDetect.ConnectionType connectionType = this.mNetworkMonitor.getCurrentConnectionType();
            this.mMonitorHandler.post(new Runnable() { // from class: com.ding.rtc.monitor.DeviceMonitor.2
                @Override // java.lang.Runnable
                public void run() {
                    DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                    if (DeviceMonitor.this.mNativeHandle != 0) {
                        DeviceMonitor deviceMonitor = DeviceMonitor.this;
                        deviceMonitor.reportNetworkType(deviceMonitor.mNativeHandle, connectionType.ordinal(), true);
                    }
                    DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                }
            });
        }
        this.mNetworkMonitor.addObserver(this);
        Logging.i("DeviceMonitor-java", "ReportDeviceInfo.");
        Context context = ContextUtils.getApplicationContext();
        String pkgName = context.getPackageName();
        try {
            PackageManager packageManager = context.getPackageManager();
            PackageInfo packageInfo = packageManager.getPackageInfo(pkgName, 0);
            int labelRes = packageInfo.applicationInfo.labelRes;
            appName = context.getResources().getString(labelRes);
        } catch (Exception e) {
            Logging.e("DeviceMonitor-java", "getAppName err: " + e.getMessage());
            appName = "";
        }
        reportHardwareInfo(this.mNativeHandle, RecvStatsReportCommon.sdk_platform, Build.VERSION.RELEASE, Build.MODEL, Build.MANUFACTURER, DeviceUuid.getDeviceID(context), pkgName, appName);
        monitorAppStatus(true);
        this.mNativeHandleLock.writeLock().unlock();
    }

    public void destroy() {
        Logging.i("DeviceMonitor-java", "destroy start");
        this.mNativeHandleLock.writeLock().lock();
        this.mNativeHandle = 0L;
        clear();
        this.mNativeHandleLock.writeLock().unlock();
        Logging.i("DeviceMonitor-java", "destroy finish");
    }

    @Override // org.webrtc.mozi.NetworkMonitor.NetworkObserver
    public void onConnectionTypeChanged(final NetworkMonitorAutoDetect.ConnectionType connectionType) {
        Logging.i("DeviceMonitor-java", "onConnectionTypeChanged,connectionType:" + connectionType.ordinal());
        if (connectionType.ordinal() != NetworkMonitorAutoDetect.ConnectionType.CONNECTION_UNKNOWN_CELLULAR.ordinal() && connectionType.ordinal() != NetworkMonitorAutoDetect.ConnectionType.CONNECTION_BLUETOOTH.ordinal() && connectionType.ordinal() != NetworkMonitorAutoDetect.ConnectionType.CONNECTION_NONE.ordinal()) {
            this.mNativeHandleLock.readLock().lock();
            Handler handler = this.mMonitorHandler;
            if (handler != null) {
                handler.post(new Runnable() { // from class: com.ding.rtc.monitor.DeviceMonitor.3
                    @Override // java.lang.Runnable
                    public void run() {
                        DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                        if (DeviceMonitor.this.mNativeHandle != 0) {
                            DeviceMonitor deviceMonitor = DeviceMonitor.this;
                            deviceMonitor.reportNetworkType(deviceMonitor.mNativeHandle, connectionType.ordinal(), false);
                        }
                        DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                    }
                });
            }
            this.mNativeHandleLock.readLock().unlock();
        }
    }

    private void clear() {
        NetworkMonitor networkMonitor = this.mNetworkMonitor;
        if (networkMonitor != null) {
            networkMonitor.removeObserver(this);
            this.mNetworkMonitor.stopMonitoring();
        }
        Handler handler = this.mMonitorHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
            this.mMonitorHandler = null;
        }
        if (this.mMonitorHandlerThread != null) {
            if (Build.VERSION.SDK_INT >= 18) {
                this.mMonitorHandlerThread.quitSafely();
            } else {
                this.mMonitorHandlerThread.quit();
            }
            this.mMonitorHandlerThread = null;
            Logging.i("DeviceMonitor-java", "destroy device monitor thread");
        }
        monitorAppStatus(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getNetWorkRSSIJNI() {
        Context context = this.mContext;
        if (context == null) {
            return -1;
        }
        WifiManager var5 = (WifiManager) context.getApplicationContext().getSystemService("wifi");
        WifiInfo wifiInfo = var5.getConnectionInfo();
        if (wifiInfo != null) {
            return wifiInfo.getRssi();
        }
        return -1;
    }

    private void monitorAppStatus(boolean bind) {
        Context context = this.mContext;
        if (context == null) {
            return;
        }
        Application app = (Application) context.getApplicationContext();
        if (bind) {
            AppFrontBackHelper appFrontBackHelper = new AppFrontBackHelper();
            this.mAppFrontBackHelper = appFrontBackHelper;
            appFrontBackHelper.bindApplication(app, new AppFrontBackHelper.OnAppStatusListener() { // from class: com.ding.rtc.monitor.DeviceMonitor.4
                @Override // com.ding.rtc.monitor.AppFrontBackHelper.OnAppStatusListener
                public void onFront() {
                    Logging.i("DeviceMonitor-java", "applicationWillBecomeActive ==");
                    DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                    if (DeviceMonitor.this.mMonitorHandler != null) {
                        DeviceMonitor.this.mMonitorHandler.post(new Runnable() { // from class: com.ding.rtc.monitor.DeviceMonitor.4.1
                            @Override // java.lang.Runnable
                            public void run() {
                                DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                                if (DeviceMonitor.this.mNativeHandle != 0) {
                                    DeviceMonitor.this.reportAppBackgroundState(DeviceMonitor.this.mNativeHandle, false);
                                }
                                DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                            }
                        });
                    }
                    DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                }

                @Override // com.ding.rtc.monitor.AppFrontBackHelper.OnAppStatusListener
                public void onBack() {
                    Logging.i("DeviceMonitor-java", "applicationWillResignActive ==");
                    DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                    if (DeviceMonitor.this.mMonitorHandler != null) {
                        DeviceMonitor.this.mMonitorHandler.post(new Runnable() { // from class: com.ding.rtc.monitor.DeviceMonitor.4.2
                            @Override // java.lang.Runnable
                            public void run() {
                                DeviceMonitor.this.mNativeHandleLock.readLock().lock();
                                if (DeviceMonitor.this.mNativeHandle != 0) {
                                    DeviceMonitor.this.reportAppBackgroundState(DeviceMonitor.this.mNativeHandle, true);
                                }
                                DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                            }
                        });
                    }
                    DeviceMonitor.this.mNativeHandleLock.readLock().unlock();
                }
            });
        } else {
            AppFrontBackHelper appFrontBackHelper2 = this.mAppFrontBackHelper;
            if (appFrontBackHelper2 != null) {
                appFrontBackHelper2.unBindApplication(app);
                this.mAppFrontBackHelper = null;
            }
        }
    }

    public static void setNeedCollectWifiRssiData(boolean needCollectWifiRssiData2) {
        needCollectWifiRssiData = needCollectWifiRssiData2;
    }

    public static void setIsInCall(boolean isInCall2) {
        isInCall = isInCall2;
    }
}
