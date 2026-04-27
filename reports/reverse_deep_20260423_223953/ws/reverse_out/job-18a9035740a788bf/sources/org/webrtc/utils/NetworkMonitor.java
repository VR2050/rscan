package org.webrtc.utils;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.webrtc.ali.ContextUtils;
import org.webrtc.utils.NetworkMonitorAutoDetect;

/* JADX INFO: loaded from: classes3.dex */
public class NetworkMonitor {
    private static final String TAG = "NetworkMonitor";
    private static NetworkMonitor instance;
    private NetworkMonitorAutoDetect autoDetector;
    private NetworkMonitorAutoDetect.ConnectionType currentConnectionType = NetworkMonitorAutoDetect.ConnectionType.CONNECTION_UNKNOWN;
    private final ArrayList<Long> nativeNetworkObservers = new ArrayList<>();
    private final ArrayList<NetworkObserver> networkObservers = new ArrayList<>();

    public interface NetworkObserver {
        void onConnectionTypeChanged(NetworkMonitorAutoDetect.ConnectionType connectionType);
    }

    private NetworkMonitor() {
    }

    @Deprecated
    public static void init(Context context) {
    }

    public static NetworkMonitor getInstance() {
        if (instance == null) {
            instance = new NetworkMonitor();
        }
        return instance;
    }

    public static void setAutoDetectConnectivityState(boolean shouldAutoDetect) {
        getInstance().setAutoDetectConnectivityStateInternal(shouldAutoDetect);
    }

    private static void assertIsTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected to be true");
        }
    }

    public void startMonitoring(long nativeObserver) {
        Log.d(TAG, "Start monitoring from native observer " + nativeObserver);
        this.nativeNetworkObservers.add(Long.valueOf(nativeObserver));
        setAutoDetectConnectivityStateInternal(true);
    }

    public void stopMonitoring(long nativeObserver) {
        Log.d(TAG, "Stop monitoring from native observer " + nativeObserver);
        setAutoDetectConnectivityStateInternal(false);
        this.nativeNetworkObservers.remove(Long.valueOf(nativeObserver));
    }

    public boolean networkBindingSupported() {
        NetworkMonitorAutoDetect networkMonitorAutoDetect = this.autoDetector;
        return networkMonitorAutoDetect != null && networkMonitorAutoDetect.supportNetworkCallback();
    }

    private static int androidSdkInt() {
        return Build.VERSION.SDK_INT;
    }

    public NetworkMonitorAutoDetect.ConnectionType getCurrentConnectionType() {
        return this.currentConnectionType;
    }

    private long getCurrentDefaultNetId() {
        NetworkMonitorAutoDetect networkMonitorAutoDetect = this.autoDetector;
        if (networkMonitorAutoDetect == null) {
            return -1L;
        }
        return networkMonitorAutoDetect.getDefaultNetId();
    }

    private void destroyAutoDetector() {
        NetworkMonitorAutoDetect networkMonitorAutoDetect = this.autoDetector;
        if (networkMonitorAutoDetect != null) {
            networkMonitorAutoDetect.destroy();
            this.autoDetector = null;
        }
    }

    private void setAutoDetectConnectivityStateInternal(boolean shouldAutoDetect) {
        if (!shouldAutoDetect) {
            destroyAutoDetector();
            return;
        }
        if (this.autoDetector == null) {
            NetworkMonitorAutoDetect networkMonitorAutoDetect = new NetworkMonitorAutoDetect(new NetworkMonitorAutoDetect.Observer() { // from class: org.webrtc.utils.NetworkMonitor.1
                @Override // org.webrtc.utils.NetworkMonitorAutoDetect.Observer
                public void onConnectionTypeChanged(NetworkMonitorAutoDetect.ConnectionType newConnectionType) {
                    NetworkMonitor.this.updateCurrentConnectionType(newConnectionType);
                }

                @Override // org.webrtc.utils.NetworkMonitorAutoDetect.Observer
                public void onNetworkConnect(NetworkMonitorAutoDetect.NetworkInformation networkInfo) {
                    NetworkMonitor.this.notifyObserversOfNetworkConnect(networkInfo);
                }

                @Override // org.webrtc.utils.NetworkMonitorAutoDetect.Observer
                public void onNetworkDisconnect(long networkHandle) {
                    NetworkMonitor.this.notifyObserversOfNetworkDisconnect(networkHandle);
                }
            }, ContextUtils.getApplicationContext());
            this.autoDetector = networkMonitorAutoDetect;
            NetworkMonitorAutoDetect.NetworkState networkState = networkMonitorAutoDetect.getCurrentNetworkState();
            updateCurrentConnectionType(NetworkMonitorAutoDetect.getConnectionType(networkState));
            updateActiveNetworkList();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateCurrentConnectionType(NetworkMonitorAutoDetect.ConnectionType newConnectionType) {
        this.currentConnectionType = newConnectionType;
        notifyObserversOfConnectionTypeChange(newConnectionType);
    }

    private void notifyObserversOfConnectionTypeChange(NetworkMonitorAutoDetect.ConnectionType newConnectionType) {
        Iterator<Long> it = this.nativeNetworkObservers.iterator();
        while (it.hasNext()) {
            it.next().longValue();
        }
        for (NetworkObserver observer : this.networkObservers) {
            observer.onConnectionTypeChanged(newConnectionType);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyObserversOfNetworkConnect(NetworkMonitorAutoDetect.NetworkInformation networkInfo) {
        Iterator<Long> it = this.nativeNetworkObservers.iterator();
        while (it.hasNext()) {
            it.next().longValue();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyObserversOfNetworkDisconnect(long networkHandle) {
        Iterator<Long> it = this.nativeNetworkObservers.iterator();
        while (it.hasNext()) {
            it.next().longValue();
        }
    }

    private void updateActiveNetworkList() {
        List<NetworkMonitorAutoDetect.NetworkInformation> networkInfoList = this.autoDetector.getActiveNetworkList();
        if (networkInfoList == null || networkInfoList.size() == 0) {
            return;
        }
        NetworkMonitorAutoDetect.NetworkInformation[] networkInfos = new NetworkMonitorAutoDetect.NetworkInformation[networkInfoList.size()];
        Iterator<Long> it = this.nativeNetworkObservers.iterator();
        while (it.hasNext()) {
            it.next().longValue();
        }
    }

    public static void addNetworkObserver(NetworkObserver observer) {
        getInstance().addNetworkObserverInternal(observer);
    }

    private void addNetworkObserverInternal(NetworkObserver observer) {
        this.networkObservers.add(observer);
    }

    public static void removeNetworkObserver(NetworkObserver observer) {
        getInstance().removeNetworkObserverInternal(observer);
    }

    private void removeNetworkObserverInternal(NetworkObserver observer) {
        this.networkObservers.remove(observer);
    }

    public static boolean isOnline() {
        NetworkMonitorAutoDetect.ConnectionType connectionType = getInstance().getCurrentConnectionType();
        return connectionType != NetworkMonitorAutoDetect.ConnectionType.CONNECTION_NONE;
    }

    static void resetInstanceForTests() {
        instance = new NetworkMonitor();
    }

    public static NetworkMonitorAutoDetect getAutoDetectorForTest() {
        return getInstance().autoDetector;
    }
}
