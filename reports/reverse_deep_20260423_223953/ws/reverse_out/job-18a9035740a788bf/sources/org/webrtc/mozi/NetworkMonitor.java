package org.webrtc.mozi;

import android.content.Context;
import android.os.Build;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;
import org.webrtc.mozi.NetworkMonitorAutoDetect;

/* JADX INFO: loaded from: classes3.dex */
public class NetworkMonitor {
    private static final String TAG = "NetworkMonitor";

    @Nullable
    private NetworkMonitorAutoDetect autoDetect;
    private final Object autoDetectLock;
    private volatile NetworkMonitorAutoDetect.ConnectionType currentConnectionType;
    private final ArrayList<Long> nativeNetworkObservers;
    private final ArrayList<NetworkObserver> networkObservers;
    private int numObservers;

    public interface NetworkObserver {
        void onConnectionTypeChanged(NetworkMonitorAutoDetect.ConnectionType connectionType);
    }

    private native void nativeNotifyConnectionTypeChanged(long j);

    private native void nativeNotifyOfActiveNetworkList(long j, NetworkMonitorAutoDetect.NetworkInformation[] networkInformationArr);

    private native void nativeNotifyOfNetworkConnect(long j, NetworkMonitorAutoDetect.NetworkInformation networkInformation);

    private native void nativeNotifyOfNetworkDisconnect(long j, long j2);

    private native void nativeNotifyOfWifiRssiUpdate(long j, int i);

    private static class InstanceHolder {
        static final NetworkMonitor instance = new NetworkMonitor();

        private InstanceHolder() {
        }
    }

    private NetworkMonitor() {
        this.autoDetectLock = new Object();
        this.nativeNetworkObservers = new ArrayList<>();
        this.networkObservers = new ArrayList<>();
        this.numObservers = 0;
        this.currentConnectionType = NetworkMonitorAutoDetect.ConnectionType.CONNECTION_UNKNOWN;
    }

    @Deprecated
    public static void init(Context context) {
    }

    public static NetworkMonitor getInstance() {
        return InstanceHolder.instance;
    }

    private static void assertIsTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected to be true");
        }
    }

    public void startMonitoring(Context applicationContext) {
        synchronized (this.autoDetectLock) {
            this.numObservers++;
            if (this.autoDetect == null) {
                this.autoDetect = createAutoDetect(applicationContext);
            }
            this.currentConnectionType = NetworkMonitorAutoDetect.getConnectionType(this.autoDetect.getCurrentNetworkState());
        }
    }

    @Deprecated
    public void startMonitoring() {
        startMonitoring(ContextUtils.getApplicationContext());
    }

    private void startMonitoring(@Nullable Context applicationContext, long nativeObserver) throws Throwable {
        Logging.d(TAG, "Start monitoring with native observer " + nativeObserver);
        startMonitoring(applicationContext != null ? applicationContext : ContextUtils.getApplicationContext());
        synchronized (this.nativeNetworkObservers) {
            this.nativeNetworkObservers.add(Long.valueOf(nativeObserver));
        }
        updateObserverActiveNetworkList(nativeObserver);
        notifyObserversOfConnectionTypeChange(this.currentConnectionType);
    }

    public void stopMonitoring() {
        synchronized (this.autoDetectLock) {
            int i = this.numObservers - 1;
            this.numObservers = i;
            if (i == 0) {
                this.autoDetect.destroy();
                this.autoDetect = null;
            }
        }
    }

    private void stopMonitoring(long nativeObserver) {
        Logging.d(TAG, "Stop monitoring with native observer " + nativeObserver);
        stopMonitoring();
        synchronized (this.nativeNetworkObservers) {
            this.nativeNetworkObservers.remove(Long.valueOf(nativeObserver));
        }
    }

    private boolean networkBindingSupported() {
        boolean z;
        synchronized (this.autoDetectLock) {
            z = this.autoDetect != null && this.autoDetect.supportNetworkCallback();
        }
        return z;
    }

    private static int androidSdkInt() {
        return Build.VERSION.SDK_INT;
    }

    public NetworkMonitorAutoDetect.ConnectionType getCurrentConnectionType() {
        return this.currentConnectionType;
    }

    private long getCurrentDefaultNetId() {
        long defaultNetId;
        synchronized (this.autoDetectLock) {
            defaultNetId = this.autoDetect == null ? -1L : this.autoDetect.getDefaultNetId();
        }
        return defaultNetId;
    }

    private NetworkMonitorAutoDetect createAutoDetect(Context appContext) {
        return new NetworkMonitorAutoDetect(new NetworkMonitorAutoDetect.Observer() { // from class: org.webrtc.mozi.NetworkMonitor.1
            @Override // org.webrtc.mozi.NetworkMonitorAutoDetect.Observer
            public void onConnectionTypeChanged(NetworkMonitorAutoDetect.ConnectionType newConnectionType) throws Throwable {
                NetworkMonitor.this.updateCurrentConnectionType(newConnectionType);
            }

            @Override // org.webrtc.mozi.NetworkMonitorAutoDetect.Observer
            public void onNetworkConnect(NetworkMonitorAutoDetect.NetworkInformation networkInfo) {
                NetworkMonitor.this.notifyObserversOfNetworkConnect(networkInfo);
            }

            @Override // org.webrtc.mozi.NetworkMonitorAutoDetect.Observer
            public void onNetworkDisconnect(long networkHandle) {
                NetworkMonitor.this.notifyObserversOfNetworkDisconnect(networkHandle);
            }

            @Override // org.webrtc.mozi.NetworkMonitorAutoDetect.Observer
            public void onWifiRssiUpdate(int rssi) {
                NetworkMonitor.this.notifyObserversOfWifiRssiUpdate(rssi);
            }
        }, appContext);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateCurrentConnectionType(NetworkMonitorAutoDetect.ConnectionType newConnectionType) throws Throwable {
        this.currentConnectionType = newConnectionType;
        notifyObserversOfConnectionTypeChange(newConnectionType);
    }

    private void notifyObserversOfConnectionTypeChange(NetworkMonitorAutoDetect.ConnectionType newConnectionType) throws Throwable {
        List<Long> nativeObservers = getNativeNetworkObserversSync();
        for (Long nativeObserver : nativeObservers) {
            nativeNotifyConnectionTypeChanged(nativeObserver.longValue());
        }
        synchronized (this.networkObservers) {
            try {
                try {
                    List<NetworkObserver> javaObservers = new ArrayList<>(this.networkObservers);
                    for (NetworkObserver observer : javaObservers) {
                        observer.onConnectionTypeChanged(newConnectionType);
                    }
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyObserversOfNetworkConnect(NetworkMonitorAutoDetect.NetworkInformation networkInfo) {
        List<Long> nativeObservers = getNativeNetworkObserversSync();
        for (Long nativeObserver : nativeObservers) {
            nativeNotifyOfNetworkConnect(nativeObserver.longValue(), networkInfo);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyObserversOfNetworkDisconnect(long networkHandle) {
        List<Long> nativeObservers = getNativeNetworkObserversSync();
        for (Long nativeObserver : nativeObservers) {
            nativeNotifyOfNetworkDisconnect(nativeObserver.longValue(), networkHandle);
        }
    }

    private void updateObserverActiveNetworkList(long nativeObserver) throws Throwable {
        synchronized (this.autoDetectLock) {
            try {
                try {
                    List<NetworkMonitorAutoDetect.NetworkInformation> networkInfoList = this.autoDetect != null ? this.autoDetect.getActiveNetworkList() : null;
                    if (networkInfoList == null || networkInfoList.size() == 0) {
                        return;
                    }
                    NetworkMonitorAutoDetect.NetworkInformation[] networkInfos = new NetworkMonitorAutoDetect.NetworkInformation[networkInfoList.size()];
                    nativeNotifyOfActiveNetworkList(nativeObserver, (NetworkMonitorAutoDetect.NetworkInformation[]) networkInfoList.toArray(networkInfos));
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyObserversOfWifiRssiUpdate(int rssi) {
        List<Long> nativeObservers = getNativeNetworkObserversSync();
        for (Long nativeObserver : nativeObservers) {
            nativeNotifyOfWifiRssiUpdate(nativeObserver.longValue(), rssi);
        }
    }

    private List<Long> getNativeNetworkObserversSync() {
        ArrayList arrayList;
        synchronized (this.nativeNetworkObservers) {
            arrayList = new ArrayList(this.nativeNetworkObservers);
        }
        return arrayList;
    }

    @Deprecated
    public static void addNetworkObserver(NetworkObserver observer) {
        getInstance().addObserver(observer);
    }

    public void addObserver(NetworkObserver observer) {
        synchronized (this.networkObservers) {
            this.networkObservers.add(observer);
        }
    }

    @Deprecated
    public static void removeNetworkObserver(NetworkObserver observer) {
        getInstance().removeObserver(observer);
    }

    public void removeObserver(NetworkObserver observer) {
        synchronized (this.networkObservers) {
            this.networkObservers.remove(observer);
        }
    }

    public static boolean isOnline() {
        NetworkMonitorAutoDetect.ConnectionType connectionType = getInstance().getCurrentConnectionType();
        return connectionType != NetworkMonitorAutoDetect.ConnectionType.CONNECTION_NONE;
    }

    @Nullable
    NetworkMonitorAutoDetect getNetworkMonitorAutoDetect() {
        NetworkMonitorAutoDetect networkMonitorAutoDetect;
        synchronized (this.autoDetectLock) {
            networkMonitorAutoDetect = this.autoDetect;
        }
        return networkMonitorAutoDetect;
    }

    int getNumObservers() {
        int i;
        synchronized (this.autoDetectLock) {
            i = this.numObservers;
        }
        return i;
    }

    static NetworkMonitorAutoDetect createAndSetAutoDetectForTest(Context context) {
        NetworkMonitor networkMonitor = getInstance();
        NetworkMonitorAutoDetect autoDetect = networkMonitor.createAutoDetect(context);
        networkMonitor.autoDetect = autoDetect;
        return autoDetect;
    }
}
