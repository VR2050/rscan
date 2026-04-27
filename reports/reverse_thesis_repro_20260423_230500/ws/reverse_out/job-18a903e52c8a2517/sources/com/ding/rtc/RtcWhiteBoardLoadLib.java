package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteBoardLoadLib {
    public static void loadDynamicLib() {
        try {
            System.loadLibrary("moziwhiteboard");
        } catch (Error var3) {
            var3.printStackTrace();
        } catch (Exception var2) {
            var2.printStackTrace();
        }
    }
}
