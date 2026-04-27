package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class CodecMonitorHelper {
    public static final String EVENT_INIT = "init";
    public static final String EVENT_RUNTIME = "runtime";
    public static final String FORMAT_HW = "hw";
    public static final String FORMAT_SW = "sw";
    private CodecMonitor codecMonitor;

    public interface CodecMonitor {
        void decoderEvent(String str, String str2, String str3);

        void encoderEvent(String str, String str2, String str3);
    }

    private static class SingletonInstance {
        private static final CodecMonitorHelper INSTANCE = new CodecMonitorHelper();

        private SingletonInstance() {
        }
    }

    public static void set(CodecMonitor codecMonitor) {
        SingletonInstance.INSTANCE.codecMonitor = codecMonitor;
    }

    public static void encoderEvent(String event, String format, String cause) {
        CodecMonitor codecMonitor = SingletonInstance.INSTANCE.codecMonitor;
        if (codecMonitor != null) {
            codecMonitor.encoderEvent(event, format, cause);
        }
    }

    public static void decoderEvent(String event, String format, String cause) {
        CodecMonitor codecMonitor = SingletonInstance.INSTANCE.codecMonitor;
        if (codecMonitor != null) {
            codecMonitor.decoderEvent(event, format, cause);
        }
    }
}
