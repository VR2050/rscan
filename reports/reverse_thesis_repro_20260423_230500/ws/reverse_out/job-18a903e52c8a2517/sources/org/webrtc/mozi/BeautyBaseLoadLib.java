package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class BeautyBaseLoadLib {
    public static void loadDynamicLib(String path) {
        try {
            System.loadLibrary(path);
        } catch (Error e) {
            e.printStackTrace();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}
